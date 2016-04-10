import win32api
import win32con
import win32net
import win32security
import ntsecuritycon

from .decorators import memoize

API_VERSION = 2

sec_info = win32security.OWNER_SECURITY_INFORMATION | win32security.GROUP_SECURITY_INFORMATION | \
           win32security.DACL_SECURITY_INFORMATION

# Obtain ACCESS_SYSTEM_SECURITY right - necessary to get/set file SACLs
new_privs = ((win32security.LookupPrivilegeValue('', ntsecuritycon.SE_SECURITY_NAME), win32con.SE_PRIVILEGE_ENABLED),
             (win32security.LookupPrivilegeValue('', ntsecuritycon.SE_RESTORE_NAME), win32con.SE_PRIVILEGE_ENABLED))
pid = win32api.GetCurrentProcessId()
ph = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, 0, pid)
th = win32security.OpenProcessToken(ph, win32security.TOKEN_ALL_ACCESS)
old_privs = win32security.AdjustTokenPrivileges(th, 0, new_privs)

if old_privs:
    sec_info |= win32security.SACL_SECURITY_INFORMATION


@memoize
def getuid():
    return user2uid(win32api.GetUserName())


@memoize
def getgid():
    groups = win32net.NetUserGetLocalGroups(None, win32api.GetUserName(), 1)
    if groups and len(groups) > 0:
        sid, domain, sid_type = win32security.LookupAccountName("", groups[0])
        return win32security.ConvertSidToStringSid(sid)
    raise NotImplementedError


@memoize
def lookup_sid(sid, default=None):
    if sid == 0:
        return default
    try:
        _sid = win32security.ConvertStringSidToSid(sid)
        name, domain, sid_type = win32security.LookupAccountSid("", _sid)
        return name
    except:
        return default


@memoize
def lookup_name(name, default=None):
    if not name or name == 'None':
        return default
    try:
        sid, domain, sid_type = win32security.LookupAccountName("", name)
        return win32security.ConvertSidToStringSid(sid)
    except:
        return default


@memoize
def uid2user(uid, default=None):
    return lookup_sid(uid, default)


@memoize
def user2uid(user, default=None):
    return lookup_name(user, default)


@memoize
def gid2group(gid, default=None):
    return lookup_sid(gid, default)


@memoize
def group2gid(group, default=None):
    return lookup_name(group, default)


def acl_get(path, item, st, numeric_owner=False):
    sd = win32security.GetNamedSecurityInfo(path, win32security.SE_FILE_OBJECT, sec_info)

    sid = win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())
    group_sid = win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorGroup())
    acl = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, win32security.SDDL_REVISION_1, sec_info)

    item[b'uid'] = sid
    item[b'gid'] = group_sid

    if not numeric_owner:
        item[b'user'] = uid2user(sid)
        item[b'group'] = gid2group(group_sid)
    else:
        item[b'user'] = item[b'group'] = None

    item[b'acl_access'] = acl


def acl_set(path, item, numeric_owner=False):
    sid = item[b'uid']
    group_sid = item[b'gid']
    acl = item[b'acl_access']

    if not numeric_owner:
        sid = lookup_name(item[b'user'], sid)
        group_sid = lookup_name(item[b'group'], group_sid)

    dacl = None
    sacl = None

    if acl:
        sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(acl.decode('utf-8'), win32security.SDDL_REVISION_1)
        dacl = sd.GetSecurityDescriptorDacl()
        if sec_info & win32security.SACL_SECURITY_INFORMATION:
            sacl = sd.GetSecurityDescriptorSacl()

    owner = None
    group_owner = None

    if sid and len(sid) > 0:
        owner = win32security.ConvertStringSidToSid(sid)

    if group_sid and len(group_sid) > 0:
        group_owner = win32security.ConvertStringSidToSid(group_sid.decode('utf-8'))

    win32security.SetNamedSecurityInfo(path, win32security.SE_FILE_OBJECT, sec_info, owner, group_owner, dacl, sacl)
