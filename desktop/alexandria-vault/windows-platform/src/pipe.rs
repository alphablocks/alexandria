//! Local-only, SID-restricted, token-authenticated transport. Tokio provides
//! cancel-safe deadline-bounded overlapped I/O; never blocking FlushFileBuffers.
//! A bare write/drop is not a delivery guarantee: production RPC must await its
//! bounded client acknowledgement before releasing the server pipe handle.
use crate::{
    check,
    identity::{check_process, current_sid, Descriptor},
    Result,
};
use std::{
    io::{Read, Write},
    os::windows::io::AsRawHandle,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions},
    runtime::Runtime,
};
use windows_sys::Win32::{
    Storage::FileSystem::SECURITY_IDENTIFICATION,
    System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId},
};
pub fn name() -> Result<String> {
    Ok(format!(r"\\.\pipe\Alexandria.vault.v1.{}", current_sid()?))
}
fn runtime() -> Result<Arc<Runtime>> {
    Ok(Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
    ))
}
enum Channel {
    Server(NamedPipeServer),
    Client(NamedPipeClient),
}
pub struct Pipe {
    io: Channel,
    rt: Arc<Runtime>,
    deadline: Instant,
}
pub struct Listener {
    server: NamedPipeServer,
    rt: Arc<Runtime>,
    name: String,
}
fn create(rt: &Runtime, name: &str, first: bool) -> Result<NamedPipeServer> {
    let sd = Descriptor::owner_only(false)?;
    let mut sa = sd.attributes();
    let _enter = rt.enter();
    Ok(unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .max_instances(2)
            .in_buffer_size(72 * 1024)
            .out_buffer_size(72 * 1024)
            .create_with_security_attributes_raw(name, (&mut sa as *mut _) as *mut _)?
    })
}
impl Listener {
    pub fn bind() -> Result<Self> {
        let rt = runtime()?;
        let name = name()?;
        let server = create(&rt, &name, true)?;
        Ok(Self { server, rt, name })
    }
    pub fn accept(&mut self) -> Result<Pipe> {
        self.rt.block_on(self.server.connect())?;
        // Reserve the next instance before handing off this connection, keeping
        // namespace ownership continuously until the service exits.
        let next = create(&self.rt, &self.name, false)?;
        let connected = std::mem::replace(&mut self.server, next);
        let mut pid = 0;
        unsafe {
            check(
                GetNamedPipeClientProcessId(connected.as_raw_handle(), &mut pid) != 0,
                "DENIED",
            )?;
        }
        check_process(pid)?;
        Ok(Pipe {
            io: Channel::Server(connected),
            rt: self.rt.clone(),
            deadline: Instant::now() + Duration::from_secs(2),
        })
    }
}
impl Pipe {
    pub fn connect() -> Result<Self> {
        let rt = runtime()?;
        let end = Instant::now() + Duration::from_secs(5);
        let client = loop {
            let result = {
                let _e = rt.enter();
                ClientOptions::new()
                    .security_qos_flags(SECURITY_IDENTIFICATION)
                    .open(name()?)
            };
            match result {
                Ok(c) => break c,
                Err(e) if e.raw_os_error() == Some(231) && Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(_) => return Err(crate::Error("UNAVAILABLE")),
            }
        };
        let mut pid = 0;
        unsafe {
            check(
                GetNamedPipeServerProcessId(client.as_raw_handle(), &mut pid) != 0,
                "DENIED",
            )?;
        }
        check_process(pid)?;
        Ok(Self {
            io: Channel::Client(client),
            rt,
            deadline: end,
        })
    }
    fn left(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .ok_or(std::io::ErrorKind::TimedOut.into())
    }
}
impl Read for Pipe {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let left = self.left()?;
        self.rt.block_on(async {
            tokio::time::timeout(left, async {
                match &mut self.io {
                    Channel::Server(p) => p.read(b).await,
                    Channel::Client(p) => p.read(b).await,
                }
            })
            .await
            .map_err(|_| std::io::ErrorKind::TimedOut)?
        })
    }
}
impl Write for Pipe {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let left = self.left()?;
        self.rt.block_on(async {
            tokio::time::timeout(left, async {
                match &mut self.io {
                    Channel::Server(p) => p.write(b).await,
                    Channel::Client(p) => p.write(b).await,
                }
            })
            .await
            .map_err(|_| std::io::ErrorKind::TimedOut)?
        })
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
