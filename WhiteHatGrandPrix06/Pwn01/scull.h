/* ioctl command encoding: 32 bits total, command in lower 16 bits,
* size of the parameter structure in the lower 14 bits of the
* upper 16 bits.
* Encoding the size of the parameter structure in the ioctl request
* is useful for catching programs compiled with old versions
* and to avoid overwriting user space outside the user buffer area.
* The highest 2 bits are reserved for indicating the ``access mode''.
* NOTE: This limits the max parameter size to 16kB -1 !
*/

/*
* The following is for compatibility across the various Linux
* platforms.  The generic ioctl numbering scheme doesn't really enforce
* a type field.  De facto, however, the top 8 bits of the lower 16
* bits are indeed used as a type field, so we might just as well make
* this explicit here.  Please be sure to use the decoding macros
* below from now on.
*/
#define _IOC_NRBITS	8
#define _IOC_TYPEBITS	8

/*
* Let any architecture override either of the following before
* including this file.
*/

#ifndef _IOC_SIZEBITS
# define _IOC_SIZEBITS	14
#endif

#ifndef _IOC_DIRBITS
# define _IOC_DIRBITS	2
#endif

#define _IOC_NRMASK	((1 << _IOC_NRBITS)-1)
#define _IOC_TYPEMASK	((1 << _IOC_TYPEBITS)-1)
#define _IOC_SIZEMASK	((1 << _IOC_SIZEBITS)-1)
#define _IOC_DIRMASK	((1 << _IOC_DIRBITS)-1)

#define _IOC_NRSHIFT	0
#define _IOC_TYPESHIFT	(_IOC_NRSHIFT+_IOC_NRBITS)
#define _IOC_SIZESHIFT	(_IOC_TYPESHIFT+_IOC_TYPEBITS)
#define _IOC_DIRSHIFT	(_IOC_SIZESHIFT+_IOC_SIZEBITS)

/*
* Direction bits, which any architecture can choose to override
* before including this file.
*
* NOTE: _IOC_WRITE means userland is writing and kernel is
* reading. _IOC_READ means userland is reading and kernel is writing.
*/

#ifndef _IOC_NONE
# define _IOC_NONE	0U
#endif

#ifndef _IOC_WRITE
# define _IOC_WRITE	1U
#endif

#ifndef _IOC_READ
# define _IOC_READ	2U
#endif

#define _IOC(dir,type,nr,size) \
(((dir)  << _IOC_DIRSHIFT) | \
	((type) << _IOC_TYPESHIFT) | \
	((nr)   << _IOC_NRSHIFT) | \
	((size) << _IOC_SIZESHIFT))

#ifndef __KERNEL__
#define _IOC_TYPECHECK(t) (sizeof(t))
#endif

/*
* Used to create numbers.
*
* NOTE: _IOW means userland is writing and kernel is reading. _IOR
* means userland is reading and kernel is writing.
*/
#define _IO(type,nr)		_IOC(_IOC_NONE,(type),(nr),0)
#define _IOR(type,nr,size)	_IOC(_IOC_READ,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOW(type,nr,size)	_IOC(_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOWR(type,nr,size)	_IOC(_IOC_READ|_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOR_BAD(type,nr,size)	_IOC(_IOC_READ,(type),(nr),sizeof(size))
#define _IOW_BAD(type,nr,size)	_IOC(_IOC_WRITE,(type),(nr),sizeof(size))
#define _IOWR_BAD(type,nr,size)	_IOC(_IOC_READ|_IOC_WRITE,(type),(nr),sizeof(size))

/* used to decode ioctl numbers.. */
#define _IOC_DIR(nr)		(((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
#define _IOC_TYPE(nr)		(((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
#define _IOC_NR(nr)		(((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _IOC_SIZE(nr)		(((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK)

/* ...and for the drivers/sound files... */

#define IOC_IN		(_IOC_WRITE << _IOC_DIRSHIFT)
#define IOC_OUT		(_IOC_READ << _IOC_DIRSHIFT)
#define IOC_INOUT	((_IOC_WRITE|_IOC_READ) << _IOC_DIRSHIFT)
#define IOCSIZE_MASK	(_IOC_SIZEMASK << _IOC_SIZESHIFT)
#define IOCSIZE_SHIFT	(_IOC_SIZESHIFT)

/*
* Ioctl definitions
*/

/* Use 'k' as magic number */
#define SCULL_IOC_MAGIC 'k'
/* Please use a different 8-bit number in your code */

#define SCULL_IOCRESET _IO(SCULL_IOC_MAGIC, 0)

/*
* S means "Set" through a ptr,
* T means "Tell" directly with the argument value
* G means "Get": reply by setting through a pointer
* Q means "Query": response is on the return value
* X means "eXchange": switch G and S atomically
* H means "sHift": switch T and Q atomically
*/
#define SCULL_IOCSQUANTUM _IOW(SCULL_IOC_MAGIC, 1, int)
#define SCULL_IOCSQSET _IOW(SCULL_IOC_MAGIC, 2, int)
#define SCULL_IOCTQUANTUM _IO(SCULL_IOC_MAGIC, 3)
#define SCULL_IOCTQSET _IO(SCULL_IOC_MAGIC, 4)
#define SCULL_IOCGQUANTUM _IOR(SCULL_IOC_MAGIC, 5, int)
#define SCULL_IOCGQSET _IOR(SCULL_IOC_MAGIC, 6, int)
#define SCULL_IOCQQUANTUM _IO(SCULL_IOC_MAGIC, 7)
#define SCULL_IOCQQSET _IO(SCULL_IOC_MAGIC, 8)
#define SCULL_IOCXQUANTUM _IOWR(SCULL_IOC_MAGIC, 9, int)
#define SCULL_IOCXQSET _IOWR(SCULL_IOC_MAGIC, 10, int)
#define SCULL_IOCHQUANTUM _IO(SCULL_IOC_MAGIC, 11)
#define SCULL_IOCHQSET _IO(SCULL_IOC_MAGIC, 12)

/*
* The other entities only have "Tell" and "Query", because they're
* not printed in the book, and there's no need to have all six.
* (The previous stuff was only there to show different ways to do it.
*/
#define SCULL_P_IOCTSIZE _IO(SCULL_IOC_MAGIC, 13)
#define SCULL_P_IOCQSIZE _IO(SCULL_IOC_MAGIC, 14)
/* ... more to come */
#define SCULL_IOCSHIFT _IO(SCULL_IOC_MAGIC, 15)
