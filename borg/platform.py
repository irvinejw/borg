import sys

if sys.platform.startswith('linux'):  # pragma: linux only
    from .platform_linux import acl_get, acl_set, API_VERSION
    from .platform_posix import getuid, getgid, uid2user, user2uid, gid2group, group2gid
elif sys.platform.startswith('freebsd'):  # pragma: freebsd only
    from .platform_freebsd import acl_get, acl_set, API_VERSION
    from .platform_posix import getuid, getgid, uid2user, user2uid, gid2group, group2gid
elif sys.platform == 'darwin':  # pragma: darwin only
    from .platform_darwin import acl_get, acl_set, API_VERSION
    from .platform_posix import getuid, getgid, uid2user, user2uid, gid2group, group2gid
else:  # pragma: unknown platform only
    API_VERSION = 2

    def acl_get(path, item, st, numeric_owner=False):
        pass

    def acl_set(path, item, numeric_owner=False):
        pass

    def getuid():
        pass

    def getgid():
        pass

    def uid2user(uid, default=None):
        pass

    def user2uid(user, default=None):
        pass

    def gid2group(gid, default=None):
        pass

    def group2gid(group, default=None):
        pass
