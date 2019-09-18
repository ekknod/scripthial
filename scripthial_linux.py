import os
import math
from ctypes import *
libc = CDLL('libc.so.6')
#
# ekknod@2019
#


g_glow = True
g_rcs = False
g_aimbot = True
g_aimbot_rcs = True
g_aimbot_head = False
g_aimbot_fov = 1.0 / 180.0
g_aimbot_smooth = 5.0
g_aimbot_key = 107
g_triggerbot_key = 111
g_exit_key = 72

g_old_punch = 0
g_previous_tick = 0
g_current_tick = 0


class TimeVal(Structure):
    _fields_ = [('sec', c_long), ('u_sec', c_long)]


class InputEvent(Structure):
    _fields_ = [('time', TimeVal), ('type', c_uint16), ('code', c_uint16), ('value', c_int)]


class Vector3(Structure):
    _fields_ = [('x', c_float), ('y', c_float), ('z', c_float)]


class MouseInput:
    def __init__(self):
        self.handle = -1
        device_name = 'event-mouse'
        for device in os.listdir('/dev/input/by-id/'):
            if device[-device_name.__len__():] == device_name:
                self.handle = os.open('/dev/input/by-id/' + device, os.O_WRONLY)
                break
        if self.handle == -1:
            raise Exception('[!]Input::__init__')

    def __del__(self):
        if self.handle != -1:
            libc.close(self.handle)

    def __send_input(self, input_type, code, value):
        start = InputEvent()
        end = InputEvent()

        libc.gettimeofday(pointer(start.time), 0)
        start.type = input_type
        start.code = code
        start.value = value
        libc.gettimeofday(pointer(end.time), 0)

        libc.write(self.handle, pointer(start), sizeof(start))
        libc.write(self.handle, pointer(end), sizeof(end))

    def click(self):
        self.__send_input(0x01, 0x110, 1)
        libc.usleep(10000)
        self.__send_input(0x01, 0x110, 0)

    def move(self, x, y):
        self.__send_input(0x02, 0, x)
        self.__send_input(0x02, 1, y)


class Process:
    @staticmethod
    def get_process_id(process_name):
        for i in os.listdir('/proc/'):
            try:
                temp_name = os.readlink('/proc/' + i + '/exe')[-len(process_name):]
            except:
                continue
            if temp_name == process_name:
                return i
        return 0

    @staticmethod
    def get_process_base(process_id, skip=True):
        result = 0
        file = open('/proc/' + process_id + '/maps')
        for i in file:
            if i.find('gnu/ld-') != -1:
                result = int(i[0:i.index('-')], 16)
                if skip:
                    break
        return result

    def __init__(self, process_name):
        pid = self.get_process_id(process_name)
        if pid == 0:
            raise Exception('[!]Process::get_process_id')

        self.maps = self.get_process_base(pid, False)
        if self.maps == 0:
            raise Exception('[!]Process::get_process_maps')

        self.dir = '/proc/' + pid + '/mem'
        self.handle = os.open(self.dir, os.O_RDWR)
        if self.handle == -1:
            raise Exception('[!]Process::open')

        if self.read_i8(self.get_process_base(pid) + 0x12) == 62:
            self.wow64 = False
            self.maps = self.read_i64(self.maps + 0x60)
        else:
            self.wow64 = True
            self.maps = self.read_i32(self.maps + 0x40)

    def __del__(self):
        if self.handle != -1:
            libc.close(self.handle)

    def exists(self):
        return os.access(self.dir, os.F_OK)

    def get_library(self, name):
        maps = self.maps
        offsets = [0x0C, 0x04] if self.wow64 else [0x18, 0x08]
        while 1:
            maps = self.read_i64(maps + offsets[0], offsets[1])
            if maps == 0:
                break
            temp = self.read_i64(maps + offsets[1], offsets[1])
            if temp == 0:
                continue
            library_name = self.read_string(temp, 256)
            if library_name[-name.__len__():] == name.encode('ascii', 'ignore'):
                return maps
        return 0

    def get_export(self, library, name):
        if library == 0:
            return 0
        offsets = [0x20, 0x10, 0x04] if self.wow64 else [0x40, 0x18, 0x08]
        str_tab = self.read_i64(library + offsets[0] + 5 * offsets[2], offsets[2])
        str_tab = self.read_i64(str_tab + offsets[2], offsets[2])
        sym_tab = self.read_i64(library + offsets[0] + 6 * offsets[2], offsets[2])
        sym_tab = self.read_i64(sym_tab + offsets[2], offsets[2])
        st_name = 1
        sym_tab += offsets[1]
        while st_name != 0:
            sym_name = self.read_string(str_tab + st_name)
            if sym_name == name.encode('ascii', 'ignore'):
                sym_tab = self.read_i64(sym_tab + offsets[2], offsets[2])
                return sym_tab + self.read_i64(library, offsets[2])
            sym_tab += offsets[1]
            st_name = self.read_i32(sym_tab)
        return 0

    def read_i8(self, address, length=1):
        buffer = c_int8()
        libc.pread(self.handle, pointer(buffer), length, c_long(address))
        return buffer.value

    def write_i8(self, address, value):
        buffer = c_int8(value)
        return libc.pwrite(self.handle, pointer(buffer), 1, c_long(address))

    def read_i16(self, address, length=2):
        buffer = c_int16()
        if libc.pread(self.handle, pointer(buffer), length, c_long(address)) == -1:
            return -1
        return buffer.value

    def write_i16(self, address, value):
        buffer = c_int16(value)
        return libc.pwrite(self.handle, pointer(buffer), 2, c_long(address))

    def read_i32(self, address, length=4):
        buffer = c_int32()
        libc.pread(self.handle, pointer(buffer), length, c_long(address))
        return buffer.value

    def write_i32(self, address, value):
        buffer = c_int32(value)
        return libc.pwrite(self.handle, pointer(buffer), 4, c_long(address))

    def read_i64(self, address, length=8):
        buffer = c_int64()
        libc.pread(self.handle, pointer(buffer), length, c_long(address))
        return buffer.value

    def write_i64(self, address, value):
        buffer = c_int64(value)
        return libc.pwrite(self.handle, pointer(buffer), 8, c_long(address))

    def read_absolute(self, address, offset, length):
        return address + self.read_i32(address + offset) + length

    def read_float(self, address, length=4):
        buffer = c_float()
        libc.pread(self.handle, pointer(buffer), length, c_long(address))
        return buffer.value

    def write_float(self, address, value):
        buffer = c_float(value)
        return libc.pwrite(self.handle, pointer(buffer), 4, c_long(address))

    def read_vec3(self, address):
        buffer = Vector3()
        libc.pread(self.handle, pointer(buffer), 12, c_long(address))
        return buffer

    def read(self, address, buffer, length):
        libc.pread(self.handle, pointer(buffer), length, c_long(address))
        return buffer

    def write(self, address, buffer, length):
        return libc.pwrite(self.handle, pointer(buffer), length, c_long(address))

    def read_string(self, address, length=120):
        buffer = create_string_buffer(length)
        libc.pread(self.handle, pointer(buffer), length, c_long(address))
        return buffer.value


class VirtualTable:
    def __init__(self, table):
        self.table = table

    def function(self, index):
        return mem.read_i64(mem.read_i64(self.table) + index * 8)


class InterfaceTable:
    def __init__(self, name):
        self.table_list = mem.read_i64(mem.get_export(mem.get_library(name), 's_pInterfaceRegs'))
        if self.table_list == 0:
            raise Exception('[!]InterfaceTable::__init__')

    def get_interface(self, name):
        a0 = self.table_list
        while a0 != 0:
            if name.encode('ascii', 'ignore') == mem.read_string(mem.read_i64(a0 + 0x08))[0:-3]:
                a0 = mem.read_i64(a0)
                if mem.read_i8(a0) != 0x48:
                    a0 += mem.read_i32(a0 + 1 + 3) + 8
                else:
                    a0 = mem.read_i64(mem.read_i64(a0 + (mem.read_i32(a0 + 0 + 3) + 7)))
                return VirtualTable(a0)
            a0 = mem.read_i64(a0 + 0x10)
        raise Exception('[!]InterfaceTable::get_interface')


class NetVarTable:
    def __init__(self, name):
        self.table = 0
        a0 = vt.client.function(8)
        a0 = mem.read_i64(mem.read_i64(a0 + mem.read_i32(a0 + 0 + 3) + 7))
        while a0 != 0:
            a1 = mem.read_i64(a0 + 0x18)
            if name.encode('ascii', 'ignore') == mem.read_string(mem.read_i64(a1 + 0x18)):
                self.table = a1
                break
            a0 = mem.read_i64(a0 + 0x20)
        if self.table == 0:
            raise Exception('[!]NetVarTable::__init__')

    def get_offset(self, name):
        offset = self.__get_offset(self.table, name)
        if offset == 0:
            raise Exception('[!]NetVarTable::get_offset')
        return offset

    def __get_offset(self, address, name):
        a0 = 0
        for a1 in range(0, mem.read_i32(address + 0x8)):
            a2 = a1 * 96 + mem.read_i64(address)
            a3 = mem.read_i32(a2 + 0x48)
            a4 = mem.read_i64(a2 + 0x40)
            if a4 != 0 and mem.read_i32(a4 + 0x8) != 0:
                a5 = self.__get_offset(a4, name)
                if a5 != 0:
                    a0 += a3 + a5
            if name.encode('ascii', 'ignore') == mem.read_string(mem.read_i64(a2)):
                return a3 + a0
        return a0


class ConVar:
    def __init__(self, name):
        self.address = 0
        a0 = mem.read_i64(mem.read_i64(mem.read_i64(vt.cvar.table + 0x70)) + 0x8)
        while a0 != 0:
            if name.encode('ascii', 'ignore') == mem.read_string(mem.read_i64(a0 + 0x18)):
                self.address = a0
                break
            a0 = mem.read_i64(a0 + 0x8)
        if self.address == 0:
            raise Exception('[!]ConVar not found!')

    def get_int(self):
        a0 = c_int32()
        a1 = mem.read_i32(self.address + 0x58) ^ self.address
        libc.memcpy(pointer(a0), pointer(c_int32(a1)), 4)
        return a0.value

    def get_float(self):
        a0 = c_float()
        a1 = mem.read_i32(self.address + 0x54) ^ self.address
        libc.memcpy(pointer(a0), pointer(c_int32(a1)), 4)
        return a0.value


class InterfaceList:
    def __init__(self):
        table = InterfaceTable('client_panorama_client.so')
        self.client = table.get_interface('VClient')
        self.entity = table.get_interface('VClientEntityList')
        table = InterfaceTable('engine_client.so')
        self.engine = table.get_interface('VEngineClient')
        table = InterfaceTable('materialsystem_client.so')
        self.cvar = table.get_interface('VEngineCvar')
        table = InterfaceTable('inputsystem_client.so')
        self.input = table.get_interface('InputSystemVersion')


# glow sig: E8 ? ? ? ? 48 8B 3D ? ? ? ? BE 01 00 00 00 C7
# x????xxx????xxxxxx
class NetVarList:
    @staticmethod
    def __get_entity_list():
        return vt.entity.table - mem.read_i32(vt.entity.function(4) + 3) + 0x08

    @staticmethod
    def __get_client_state():
        a0 = vt.engine.function(18)
        a1 = mem.read_i32(a0 + 0x11 + 1) + 0x16
        a2 = mem.read_i32(a0 + a1 + 5 + 3) + 0x0C
        return mem.read_i64(a0 + a1 + a2 + 0x08) + 0x08

    def __init__(self):
        table = NetVarTable('DT_BasePlayer')
        self.m_iHealth = table.get_offset('m_iHealth')
        self.m_vecViewOffset = table.get_offset('m_vecViewOffset[0]')
        self.m_lifeState = table.get_offset('m_lifeState')
        self.m_nTickBase = table.get_offset('m_nTickBase')
        self.m_vecPunch = table.get_offset('m_aimPunchAngle')
        table = NetVarTable('DT_BaseEntity')
        self.m_iTeamNum = table.get_offset('m_iTeamNum')
        self.m_vecOrigin = table.get_offset('m_vecOrigin')
        table = NetVarTable('DT_CSPlayer')
        self.m_hActiveWeapon = table.get_offset('m_hActiveWeapon')
        self.m_iShotsFired = table.get_offset('m_iShotsFired')
        self.m_iCrossHairID = table.get_offset('m_bHasDefuser') + 0x78
        self.m_iGlowIndex = table.get_offset('m_flFlashDuration') + 0x34
        table = NetVarTable('DT_BaseAnimating')
        self.m_dwBoneMatrix = table.get_offset('m_nForceBone') + 0x2C
        table = NetVarTable('DT_BaseAttributableItem')
        self.m_iItemDefinitionIndex = table.get_offset('m_iItemDefinitionIndex')
        self.entityList = self.__get_entity_list()
        self.clientState = self.__get_client_state()
        self.getLocalPlayer = mem.read_i32(vt.engine.function(12) + 0x11)
        self.dwViewAngles = mem.read_i32(vt.engine.function(18) + 0x1A)
        self.dwMaxClients = mem.read_i32(vt.engine.function(20) + 0x0C)
        self.dwState = mem.read_i32(vt.engine.function(26) + 0x0C)
        self.dwButton = mem.read_i32(vt.input.function(15) + 0x19)
        self.dwInput = mem.read_absolute(vt.client.function(16), 3, 7)
        self.dwInput = mem.read_i64(mem.read_i64(self.dwInput))
        self.dwLastCommand = 0x8E34


class Player:
    def __init__(self, address):
        self.address = address

    def get_team_num(self):
        return mem.read_i32(self.address + nv.m_iTeamNum)

    def get_health(self):
        return mem.read_i32(self.address + nv.m_iHealth)

    def get_life_state(self):
        return mem.read_i32(self.address + nv.m_lifeState)

    def get_tick_count(self):
        return mem.read_i32(self.address + nv.m_nTickBase)

    def get_shots_fired(self):
        return mem.read_i32(self.address + nv.m_iShotsFired)

    def get_cross_index(self):
        return mem.read_i32(self.address + nv.m_iCrossHairID)

    def get_weapon(self):
        a0 = mem.read_i32(self.address + nv.m_hActiveWeapon)
        return mem.read_i64(nv.entityList + ((a0 & 0xFFF) - 1) * 0x10)

    def get_weapon_id(self):
        return mem.read_i32(self.get_weapon() + nv.m_iItemDefinitionIndex)

    def get_origin(self):
        return mem.read_vec3(self.address + nv.m_vecOrigin)

    def get_vec_view(self):
        return mem.read_vec3(self.address + nv.m_vecViewOffset)

    def get_eye_pos(self):
        v = self.get_vec_view()
        o = self.get_origin()
        return Vector3(v.x + o.x, v.y + o.y, v.z + o.z)

    def get_vec_punch(self):
        return mem.read_vec3(self.address + nv.m_vecPunch)

    def get_bone_pos(self, index):
        a0 = 0x30 * index
        a1 = mem.read_i64(self.address + nv.m_dwBoneMatrix)
        return Vector3(
            mem.read_float(a1 + a0 + 0x0C),
            mem.read_float(a1 + a0 + 0x1C),
            mem.read_float(a1 + a0 + 0x2C)
        )

    def is_valid(self):
        health = self.get_health()
        return self.address != 0 and self.get_life_state() == 0 and 0 < health < 1338


class Engine:
    @staticmethod
    def get_local_player():
        return mem.read_i32(nv.clientState + nv.getLocalPlayer) + 1

    @staticmethod
    def get_view_angles():
        return mem.read_vec3(nv.clientState + nv.dwViewAngles)

    @staticmethod
    def get_max_clients():
        return mem.read_i32(nv.clientState + nv.dwMaxClients)

    @staticmethod
    def is_in_game():
        return mem.read_i8(nv.clientState + nv.dwState) >> 2


class Entity:
    @staticmethod
    def get_client_entity(index):
        return Player(mem.read_i64(nv.entityList + index * 0x20))


class InputSystem:
    @staticmethod
    def is_button_down(button):
        a0 = mem.read_i32(vt.input.table + ((button >> 5) * 4) + nv.dwButton)
        return (a0 >> (button & 31)) & 1


class Math:
    @staticmethod
    def sin_cos(radians):
        return [math.sin(radians), math.cos(radians)]

    @staticmethod
    def rad2deg(x):
        return x * 3.141592654

    @staticmethod
    def deg2rad(x):
        return x * 0.017453293

    @staticmethod
    def angle_vec(angles):
        s = Math.sin_cos(Math.deg2rad(angles.x))
        y = Math.sin_cos(Math.deg2rad(angles.y))
        return Vector3(s[1] * y[1], s[1] * y[0], -s[0])

    @staticmethod
    def vec_normalize(vec):
        radius = 1.0 / (math.sqrt(vec.x * vec.x + vec.y * vec.y + vec.z * vec.z) + 1.192092896e-07)
        vec.x *= radius
        vec.y *= radius
        vec.z *= radius
        return vec

    @staticmethod
    def vec_angles(forward):
        if forward.y == 0.00 and forward.x == 0.00:
            yaw = 0
            pitch = 270.0 if forward.z > 0.00 else 90.0
        else:
            yaw = math.atan2(forward.y, forward.x) * 57.295779513
            if yaw < 0.00:
                yaw += 360.0
            tmp = math.sqrt(forward.x * forward.x + forward.y * forward.y)
            pitch = math.atan2(-forward.z, tmp) * 57.295779513
            if pitch < 0.00:
                pitch += 360.0
        return Vector3(pitch, yaw, 0.00)

    @staticmethod
    def vec_clamp(v):
        if 89.0 < v.x <= 180.0:
            v.x = 89.0
        if v.x > 180.0:
            v.x -= 360.0
        if v.x < -89.0:
            v.x = -89.0
        v.y = math.fmod(v.y + 180.0, 360.0) - 180.0
        v.z = 0.00
        return v

    @staticmethod
    def vec_dot(v0, v1):
        return v0.x * v1.x + v0.y * v1.y + v0.z * v1.z

    @staticmethod
    def vec_length(v):
        return v.x * v.x + v.y * v.y + v.z * v.z

    @staticmethod
    def get_fov(va, angle):
        a0 = Math.angle_vec(va)
        a1 = Math.angle_vec(angle)
        return Math.rad2deg(math.acos(Math.vec_dot(a0, a1) / Math.vec_length(a0)))


def get_target_angle(local_p, target, bone_id):
    m = target.get_bone_pos(bone_id)
    c = local_p.get_eye_pos()
    c.x = m.x - c.x
    c.y = m.y - c.y
    c.z = m.z - c.z
    c = Math.vec_angles(Math.vec_normalize(c))
    if g_aimbot_rcs and local_p.get_shots_fired() > 1:
        p = local_p.get_vec_punch()
        c.x -= p.x * 2.0
        c.y -= p.y * 2.0
        c.z -= p.z * 2.0
    return Math.vec_clamp(c)


_target = Player(0)
_target_bone = 0
_bones = [5, 4, 3, 0, 7, 8]


def target_set(target):
    global _target
    _target = target


def get_best_target(va, local_p):
    global _target_bone
    a0 = 9999.9
    for i in range(1, Engine.get_max_clients()):
        entity = Entity.get_client_entity(i)
        if not entity.is_valid():
            continue
        if not mp_teammates_are_enemies.get_int() and local_p.get_team_num() == entity.get_team_num():
            continue
        if g_aimbot_head:
            fov = Math.get_fov(va, get_target_angle(local_p, entity, 8))
            if fov < a0:
                a0 = fov
                target_set(entity)
                _target_bone = 8
        else:
            for j in range(0, _bones.__len__()):
                fov = Math.get_fov(va, get_target_angle(local_p, entity, _bones[j]))
                if fov < a0:
                    a0 = fov
                    target_set(entity)
                    _target_bone = _bones[j]
    return a0 != 9999


def aim_at_target(sensitivity, va, angle):
    global g_current_tick
    global g_previous_tick
    y = va.x - angle.x
    x = va.y - angle.y
    if y > 89.0:
        y = 89.0
    elif y < -89.0:
        y = -89.0
    if x > 180.0:
        x -= 360.0
    elif x < -180.0:
        x += 360.0
    if math.fabs(x) / 180.0 >= g_aimbot_fov:
        target_set(Player(0))
        return
    if math.fabs(y) / 89.0 >= g_aimbot_fov:
        target_set(Player(0))
        return
    x = (x / sensitivity) / 0.022
    y = (y / sensitivity) / -0.022
    if g_aimbot_smooth > 1.00:
        sx = 0.00
        sy = 0.00
        if sx < x:
            sx += 1.0 + (x / g_aimbot_smooth)
        elif sx > x:
            sx -= 1.0 - (x / g_aimbot_smooth)
        if sy < y:
            sy += 1.0 + (y / g_aimbot_smooth)
        elif sy > y:
            sy -= 1.0 - (y / g_aimbot_smooth)
    else:
        sx = x
        sy = y
    if _current_tick - g_previous_tick > 0:
        g_previous_tick = g_current_tick
        mouse.move(int(sx), int(sy))


if __name__ == "__main__":
    global mouse
    global mem
    global vt
    global nv
    global sensitivity
    global mp_teammates_are_enemies

    try:
        mouse = MouseInput()
        mem = Process('csgo_linux64')
        vt = InterfaceList()
        nv = NetVarList()
        _sensitivity = ConVar('sensitivity')
        mp_teammates_are_enemies = ConVar('mp_teammates_are_enemies')
    except Exception as e:
        print(e)
        exit(0)

    print('[*]VirtualTables')
    print('    VClient:            ' + hex(vt.client.table))
    print('    VClientEntityList:  ' + hex(vt.entity.table))
    print('    VEngineClient:      ' + hex(vt.engine.table))
    print('    VEngineCvar:        ' + hex(vt.cvar.table))
    print('    InputSystemVersion: ' + hex(vt.input.table))
    print('[*]Offsets')
    print('    EntityList:         ' + hex(nv.entityList))
    print('    ClientState:        ' + hex(nv.clientState))
    print('    GetLocalPlayer:     ' + hex(nv.getLocalPlayer))
    print('    GetViewAngles:      ' + hex(nv.dwViewAngles))
    print('    GetMaxClients:      ' + hex(nv.dwMaxClients))
    print('    IsInGame:           ' + hex(nv.dwState))
    print('[*]NetVars')
    print('    m_iHealth:          ' + hex(nv.m_iHealth))
    print('    m_vecViewOffset:    ' + hex(nv.m_vecViewOffset))
    print('    m_lifeState:        ' + hex(nv.m_lifeState))
    print('    m_nTickBase:        ' + hex(nv.m_nTickBase))
    print('    m_vecPunch:         ' + hex(nv.m_vecPunch))
    print('    m_iTeamNum:         ' + hex(nv.m_iTeamNum))
    print('    m_vecOrigin:        ' + hex(nv.m_vecOrigin))
    print('    m_hActiveWeapon:    ' + hex(nv.m_hActiveWeapon))
    print('    m_iShotsFired:      ' + hex(nv.m_iShotsFired))
    print('    m_iCrossHairID:     ' + hex(nv.m_iCrossHairID))
    print('    m_dwBoneMatrix:     ' + hex(nv.m_dwBoneMatrix))
    print('[*]Info')
    print('    Creator:            github.com/ekknod')

    while mem.exists() and not InputSystem.is_button_down(g_exit_key):
        libc.usleep(1000)
        if Engine.is_in_game():
            try:
                self = Entity.get_client_entity(Engine.get_local_player())
                fl_sensitivity = _sensitivity.get_float()
                view_angle = Engine.get_view_angles()
                if g_glow:
                    # glow_pointer = mem.read_i64(nv.dwGlowObjectManager)
                    for i in range(0, Engine.get_max_clients()):
                        entity = Entity.get_client_entity(i)
                        if not entity.is_valid():
                            continue
                        if not mp_teammates_are_enemies.get_int() and self.get_team_num() == entity.get_team_num():
                            continue
                        entity_health = entity.get_health() / 100.0
                        index = mem.read_i32(entity.address + nv.m_iGlowIndex) * 0x38
                #         mem.write_float(glow_pointer + index + 0x04, 1.0 - entity_health)  # r
                #         mem.write_float(glow_pointer + index + 0x08, entity_health)        # g
                #         mem.write_float(glow_pointer + index + 0x0C, 0.0)                  # b
                #         mem.write_float(glow_pointer + index + 0x10, 0.8)                  # a
                #         mem.write_i8(glow_pointer + index + 0x24, 1)
                #         mem.write_i8(glow_pointer + index + 0x25, 0)
                if InputSystem.is_button_down(g_triggerbot_key):
                    cross_id = self.get_cross_index()
                    if cross_id == 0:
                        continue
                    cross_target = Entity.get_client_entity(cross_id)
                    if self.get_team_num() != cross_target.get_team_num() and cross_target.get_health() > 0:
                        mouse.click()
                if g_aimbot and InputSystem.is_button_down(g_aimbot_key):
                    _current_tick = self.get_tick_count()
                    if not _target.is_valid() and not get_best_target(view_angle, self):
                        continue
                    aim_at_target(fl_sensitivity, view_angle, get_target_angle(self, _target, _target_bone))
                else:
                    target_set(Player(0))
                if g_rcs:
                    current_punch = self.get_vec_punch()
                    if self.get_shots_fired() > 1:
                        new_punch = Vector3(current_punch.x - g_old_punch.x,
                                            current_punch.y - g_old_punch.y, 0)
                        new_angle = Vector3(view_angle.x - new_punch.x * 2.0, view_angle.y - new_punch.y * 2.0, 0)
                        mouse.move(int(((new_angle.y - view_angle.y) / fl_sensitivity) / -0.022),
                                   int(((new_angle.x - view_angle.x) / fl_sensitivity) / 0.022))
                    g_old_punch = current_punch
            except ValueError:
                continue

