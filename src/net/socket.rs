use std::net::UdpSocket;

pub fn bind_socket_to_interface(sock: &UdpSocket, if_index: u32) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        #[link(name = "ws2_32")]
        extern "system" {
            fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
        }
        let raw = sock.as_raw_socket() as usize;
        let be = if_index.to_be();
        let bytes = be.to_ne_bytes();
        let ret = unsafe { setsockopt(raw, 0, 31, bytes.as_ptr(), 4) };
        if ret != 0 {
            return Err("setsockopt(IP_UNICAST_IF) failed".to_string());
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = sock.as_raw_fd();
        let idx = if_index as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                25, // IP_BOUND_IF
                &idx as *const _ as *const libc::c_void,
                std::mem::size_of_val(&idx) as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err("setsockopt(IP_BOUND_IF) failed".to_string());
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = (sock, if_index);
        Ok(())
    }
}

pub fn set_socket_buffers(sock: &UdpSocket, size: i32) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        #[link(name = "ws2_32")]
        extern "system" {
            fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
        }
        const SOL_SOCKET: i32 = 0xFFFF;
        const SO_RCVBUF: i32 = 0x1002;
        const SO_SNDBUF: i32 = 0x1001;

        let raw = sock.as_raw_socket() as usize;
        let bytes = size.to_ne_bytes();
        unsafe {
            let _ = setsockopt(raw, SOL_SOCKET, SO_RCVBUF, bytes.as_ptr(), 4);
            let _ = setsockopt(raw, SOL_SOCKET, SO_SNDBUF, bytes.as_ptr(), 4);
        }
        Ok(())
    }

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = sock.as_raw_fd();
        let size_c = size as libc::c_int;
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size_c as *const _ as *const libc::c_void,
                std::mem::size_of_val(&size_c) as libc::socklen_t,
            );
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &size_c as *const _ as *const libc::c_void,
                std::mem::size_of_val(&size_c) as libc::socklen_t,
            );
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        let _ = (sock, size);
        Ok(())
    }
}
