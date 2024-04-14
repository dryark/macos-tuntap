#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <sys/kern_event.h>
#include <sys/kern_control.h>

#define KERN_SUCCESS (0)
#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#define UTUN_OPT_IFNAME (2)

static int create_utun_interface( u_int32_t num, size_t ifname_len, char *ifname ) {
    struct sockaddr_ctl addr;
    struct ctl_info info;
    
    int fd = socket( PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL );
    
    bzero( &info, sizeof(info) );
    strncpy( info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME );
    if( ioctl(fd, CTLIOCGINFO, &info) != KERN_SUCCESS ) {
        close(fd);
        return -1;
    }
    
    addr.sc_id = info.ctl_id;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = num + 1; // utunX where X is sc.sc_unit -1
    if( connect( fd, (struct sockaddr *) &addr, sizeof(addr)) != KERN_SUCCESS ) {
        close(fd);
        return -1;
    }
    
    if( getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, (socklen_t *) &ifname_len) != KERN_SUCCESS ) {
        close(fd);
        return -1;
    }
    
    return fd;
}

static TunTap *tuntap__new( PyObject *args, PyObject *kwds ) {
    TunTap *tuntap = (TunTap *) malloc( sizeof( TunTap ) );
    int i = 0;
    int fd;
    
    char name[ sizeof(tuntap->name) ];
    while( -1 == ( fd = create_utun_interface( i, sizeof(name), name ) ) ) {
        ++i;
    }
    if( -1 == fd ) {
        raise_error("Failed to create tun device");
    }
    tuntap->fd = fd;
    strcpy( tuntap->name, name );
    return tuntap;
}

static void tuntap__delete( TunTap *self ) {
    if( tuntap->fd >= 0 ) close( tuntap->fd );
    free( self );
}

static char *tuntap_get_name( TunTap *self ) {
    return tuntap->name;
}

static int tuntap_set_addr( TunTap *self, PyObject *value ) {
    pytun_tuntap_t *tuntap = (pytun_tuntap_t *) self;
    int ret = 0;
    char cmd[1024];
    
    PyObject *tmp_addr;
    const char *addr;
    
    tmp_addr = PyUnicode_AsASCIIString( value );
    addr = tmp_addr != NULL ? PyBytes_AS_STRING( tmp_addr ) : NULL;
    if( addr == NULL ) {
        ret = -1;
        goto out;
    }
    
    sprintf( cmd, "ifconfig %s inet6 %s prefixlen 64", tuntap->name, addr );
    if( system( cmd ) != 0 ) {
        ret = -1;
        goto out;
    }
    
    out:
    Py_XDECREF( tmp_addr );
    
    return ret;
}

static long tuntap_get_mtu( TunTap *tuntap ) {
    struct ifreq req;
    int ret;
    
    memset( &req, 0, sizeof(req) );
    strcpy( req.ifr_name, tuntap->name );
    
    ret = ioctl( tuntap->fd, SIOCGIFMTU, &req );
    
    if( ret < 0 ) {
        raise_error_from_errno();
        return NULL;
    }
    
    return req.ifr_mtu;
}

static int tuntap_set_mtu( TunTap *tuntap, PyObject *value ) {
    struct ifreq req;
    int mtu;
    int err;
    
    mtu = (int) PyLong_AsLong(value);
    if (mtu <= 0) {
        if (!PyErr_Occurred()) {
            raise_error("Bad MTU, should be > 0");
        }
        return -1;
    }
    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    req.ifr_mtu = mtu;
    
    err = ioctl(tuntap->fd, SIOCSIFMTU, &req);
    
    if( err < 0 ) {
        raise_error_from_errno();
        return -1;
    }
    
    return 0;
}

static void tuntap_close( TunTap *tuntap ) {
    if( tuntap->fd >= 0 ) {
        close( tuntap->fd );
        tuntap->fd = -1;
    }
}

static void tuntap_up( TunTap *tuntap ) {
    struct ifreq req;
    
    memset( &req, 0, sizeof(req) );
    strcpy( req.ifr_name, tuntap->name );
    if( ioctl( tuntap->fd, SIOCGIFFLAGS, &req ) < 0 ) {
        return NULL;
    }
    if( !( req.ifr_flags & IFF_UP ) ) {
        req.ifr_flags |= IFF_UP;
        if( ioctl( tuntap->fd, SIOCSIFFLAGS, &req ) < 0 ) {
            return NULL;
        }
    }
}

static void tuntap_down( TunTap *tuntap ) {
    struct ifreq req;
    
    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    if( ioctl( tuntap->fd, SIOCGIFFLAGS, &req ) < 0 ) {
        raise_error_from_errno();
        return NULL;
    }
    if( req.ifr_flags & IFF_UP ) {
        req.ifr_flags &= ~IFF_UP;
        if( ioctl( tuntap->fd, SIOCSIFFLAGS, &req ) < 0 ) {
            raise_error_from_errno();
            return NULL;
        }
    }
}

static PyObject *tuntap_read( TunTap *tuntap, PyObject *args ) {
    unsigned int rdlen;
    ssize_t outlen;
    PyObject *buf;
    
    if (!PyArg_ParseTuple(args, "I:read", &rdlen)) {
        return NULL;
    }
    
    // Allocate a new string
    buf = PyBytes_FromStringAndSize(NULL, rdlen);
    if (buf == NULL) {
        return NULL;
    }
    // Read data
    outlen = read(tuntap->fd, PyBytes_AS_STRING(buf), rdlen);
    
    if (outlen < 0) {
        // An error occurred, release the string and return an error
        raise_error_from_errno();
        return NULL;
    }
    if (outlen < rdlen) {
        // We did not read as many bytes as we anticipated, resize the string if possible and be successful.
        if (_PyBytes_Resize(&buf, outlen) < 0) {
            return NULL;
        }
    }
    
    return buf;
}
// pytun_tuntap_read(size) -> read at most size bytes, returned as a string.

static ssize_t tuntap_write( TunTap *tuntap, PyObject *args ) {
    char *buf;
    Py_ssize_t len;
    ssize_t written;
    
    if( !PyArg_ParseTuple( args, "s#:write", &buf, &len ) ) {
        return NULL;
    }
    
    written = write( tuntap->fd, buf, len );
    if( written < 0 ) {
        raise_error_from_errno();
        return NULL;
    }
    
    return written;
}

static PyObject *tuntap_fileno( TunTap *self ) {
    return self->fd;
}

#ifdef IFF_MULTI_QUEUE
static void tuntap_mq_attach( TunTap *tuntap, PyObject* args ) {
    PyObject* tmp = NULL;
    struct ifreq req;
    int ret;
    
    if( !PyArg_ParseTuple( args, "|O!:attach", &PyBool_Type, &tmp ) ) {
        return;
    }
    
    memset( &req, 0, sizeof(req) );
    if( tmp == NULL || tmp == Py_True ) {
        req.ifr_flags = IFF_ATTACH_QUEUE;
    }
    else {
        req.ifr_flags = IFF_DETACH_QUEUE;
    }
    
    ret = ioctl( tuntap->fd, TUNSETQUEUE, &req );
    if (ret < 0) {
        raise_error_from_errno();
    }
}
// tuntap_mq_attach(flag) -> None. Enable the queue if flags is True else disable the queue.
#endif