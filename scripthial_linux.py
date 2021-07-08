import os
import math
from ctypes import *
libc = CDLL("libc.so.6")
#
# ekknod@2019
#


g_horizontal_only = True
g_glow = True
g_rcs = True
g_aimbot = True
g_aimbot_rcs = True
g_aimbot_head = False
g_aimbot_fov = 2.0 / 180.0
g_aimbot_smooth = 4.5
g_aimbot_key = 107
g_triggerbot_key = 111
g_exit_key = 72

g_old_punch = 0
g_previous_tick = 0
g_current_tick = 0


class TimeVal(Structure):
    _fields_ = [("sec", c_long), ("u_sec", c_long)]


class InputEvent(Structure):
    _fields_ = [("time", TimeVal), ("type", c_uint16), ("code", c_uint16), ("value", c_int)]


class Vector3(Structure):
    _fields_ = [("x", c_float), ("y", c_float), ("z", c_float)]


class MouseInput:
    def __init__(self):
        self.handle = -1
        device_name = "event-mouse"
        for device in os.listdir("/dev/input/by-path/"):
            if device[-device_name.__len__():] == device_name:
                self.handle = os.open("/dev/input/by-path/" + device, os.O_WRONLY)
                return
        raise Exception("Input [" + device_name + "] not found!")

    def __del__(self):
        if self.handle != -1:
            os.close(self.handle)

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
        libc.usleep(50000)
        self.__send_input(0x01, 0x110, 0)

    def move(self, x, y):
        self.__send_input(0x02, 0, x)
        self.__send_input(0x02, 1, y)


class Process:
    @staticmethod
    def get_process_id(process_name):
        for i in os.listdir("/proc/"):
            try:
                temp_name = os.readlink("/proc/" + i + "/exe")[-len(process_name):]
            except:
                continue
            if temp_name == process_name:
                return i  
        raise Exception("Process [" + process_name + "] not found!")

    @staticmethod
    def get_process_base(process_id, process_name):
        file = open('/proc/' + str(process_id) + '/maps')
        for i in file:
            if i.find(process_name) != -1:
                return int(i[0:i.index('-')], 16)
        return 0

    def __get_elf_address(self, base, tag):
        a0 = base + self.read_i32(base + 0x20)
        for a1 in range(0, self.read_i16(base + 0x38)):
            a2 = 56 * a1 + a0
            if self.read_i32(a2) == tag:
                return a2
        raise Exception("Process::__get_elf_address")

    def get_process_maps(self, pid, name):
        a0 = self.get_process_base(pid, name)
        a1 = self.__get_elf_address(a0, 2)
        a2 = self.__get_elf_address(a0, 1)
        a2 = a0 - self.read_i64(a2 + 0x10)
        a2 = self.read_i64(a1 + 0x10) + a2
        while self.read_i64(a2) != 0:
            if self.read_i64(a2) == 3:
                a3 = self.read_i64(a2 + 8)
                a4 = self.read_i64(a3 + 8)
                return a4
            a2 = a2 + 8
        raise Exception("Process::get_process_maps")

    def __init__(self, process_name):
        self.handle = -1
        pid = self.get_process_id(process_name)
        self.dir = "/proc/" + pid + "/mem"
        self.handle = os.open(self.dir, os.O_RDWR)
        self.maps = self.get_process_maps(pid, process_name)

    def __del__(self):
        if self.handle != -1:
            os.close(self.handle)

    def exists(self):
        return os.access(self.dir, os.F_OK)

    def get_library(self, name):
        maps = self.maps
        mod  = 0
        while 1:
            maps = self.read_i64(maps + 0x18, 8)
            if maps == 0:
                break
            temp = self.read_i64(maps + 0x08, 8)
            if temp == 0:
                continue
            library_name = self.read_string(temp, 256)
            if library_name[-name.__len__():] == name.encode("ascii", "ignore"):
                mod = maps
        if mod == 0:
            raise Exception("Library [" + name + "] not found!")
        return mod

    def get_export(self, library, name):
        if library == 0:
            return 0
        str_tab = self.read_i64(library + 0x40 + 5 * 8)
        str_tab = self.read_i64(str_tab + 8)
        sym_tab = self.read_i64(library + 0x40 + 6 * 8)
        sym_tab = self.read_i64(sym_tab + 8)
        st_name = 1
        sym_tab += 0x18
        while st_name != 0:
            sym_name = self.read_string(str_tab + st_name)
            if sym_name == name.encode("ascii", "ignore"):
                sym_tab = self.read_i64(sym_tab + 8)
                return sym_tab + self.read_i64(library)
            sym_tab += 0x18
            st_name = self.read_i32(sym_tab)
        raise Exception("Export [" + name + "] not found!")

    def find_pattern(self, start, library_name, pattern, mask):
        a0 = self.get_library(library_name)
        a1 = self.read_i64(a0)
        a2 = a1 + self.read_i32(a1 + 0x20)
        a3 = self.read_i32(a2 + 0x10)
        a4 = self.read_i32(a2 + 0x28)
        a5 = create_string_buffer(a4)
        libc.pread(self.handle, pointer(a5), a4, c_long(a1 + a3))
        a5 = cast(a5, POINTER(c_uint8))
        for index in range(start, a4):
            a6 = 0
            for a7 in range(0, pattern.__len__()):
                if mask[a7] == 'x' and a5[index + a7] != pattern[a7]:
                    break
                a6 = a6 + 1
            if a6 == pattern.__len__():
                return a1 + a3 + index
        raise Exception("[!]Process::find_pattern")

    def read_i8(self, address, length=1):
        buffer = c_int8()
        libc.pread(self.handle, pointer(buffer), length, c_long(address))
        return buffer.value

    def write_i8(self, address, value):
        buffer = c_int8(value)
        return libc.pwrite(self.handle, pointer(buffer), 1, c_long(address))

    def read_i16(self, address, length=2):
        buffer = c_int16()
        libc.pread(self.handle, pointer(buffer), length, c_long(address))
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
        self.table_list = mem.read_i64(mem.get_export(mem.get_library(name), "s_pInterfaceRegs"))

    def get_interface(self, name):
        a0 = self.table_list
        while a0 != 0:
            if name.encode("ascii", "ignore") == mem.read_string(mem.read_i64(a0 + 0x08))[0:-3]:
                a0 = mem.read_i64(a0)
                if mem.read_i8(a0) != 0x48:
                    a0 = a0 + mem.read_i32(a0 + 1 + 3) + 8
                else:
                    a0 = mem.read_i64(mem.read_i64(a0 + (mem.read_i32(a0 + 0 + 3) + 7)))
                return VirtualTable(a0)
            a0 = mem.read_i64(a0 + 0x10)
        raise Exception("Interface [" + name + "] not found!")


class NetVarTable:
    def __init__(self, name):
        self.table = 0
        a0 = vt.client.function(8)
        a0 = mem.read_i64(mem.read_i64(a0 + mem.read_i32(a0 + 0 + 3) + 7))
        while a0 != 0:
            a1 = mem.read_i64(a0 + 0x18)
            if name.encode("ascii", "ignore") == mem.read_string(mem.read_i64(a1 + 0x18)):
                self.table = a1
                return
            a0 = mem.read_i64(a0 + 0x20)
        raise Exception("NetvarTable [" + name + "] not found!")

    def get_offset(self, name):
        offset = self.__get_offset(self.table, name)
        if offset == 0:
            raise Exception("Offset [" + name + "] not found!")
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
            if name.encode("ascii", "ignore") == mem.read_string(mem.read_i64(a2)):
                return a3 + a0
        return a0


class ConVar:
    def __init__(self, name):
        self.address = 0
        a0 = mem.read_i64(mem.read_i64(mem.read_i64(vt.cvar.table + 0x70)) + 0x8)
        while a0 != 0:
            if name.encode("ascii", "ignore") == mem.read_string(mem.read_i64(a0 + 0x18)):
                self.address = a0
                return
            a0 = mem.read_i64(a0 + 0x8)
        raise Exception("Convar [" + name + "] not found!")

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
        table = InterfaceTable("client_client.so")
        self.client = table.get_interface("VClient")
        self.entity = table.get_interface("VClientEntityList")
        table = InterfaceTable("engine_client.so")
        self.engine = table.get_interface("VEngineClient")
        table = InterfaceTable("materialsystem_client.so")
        self.cvar = table.get_interface("VEngineCvar")
        table = InterfaceTable("inputsystem_client.so")
        self.input = table.get_interface("InputSystemVersion")



class NetVarList:
    @staticmethod
    def __get_entity_list():
        return vt.entity.table - mem.read_i32(vt.entity.function(4) + 3) + 0x08

    @staticmethod
    def __get_client_state():
        a0 = vt.engine.function(18)
        a1 = mem.read_i32(a0 + 0x11 + 0x1) + 0x16 # call 0x35da0
        a2 = mem.read_i32(a0 + a1 + 5 + 3) + 0x0C # lea rax, [rip+0x2b21c84]
        a2 = mem.read_i64(a0 + a1 + a2 + 0x08)    # mov rax, QWORD PTR[rax+rdi+0x8]
        a2 += 0x08                                # add rax, 0x8
        return a2                                 # ret

    def __init__(self):
        table = NetVarTable("DT_BasePlayer")
        self.m_iHealth = table.get_offset("m_iHealth")
        self.m_vecViewOffset = table.get_offset("m_vecViewOffset[0]")
        self.m_lifeState = table.get_offset("m_lifeState")
        self.m_nTickBase = table.get_offset("m_nTickBase")
        self.m_vecPunch = table.get_offset("m_aimPunchAngle")
        table = NetVarTable("DT_BaseEntity")
        self.m_iTeamNum = table.get_offset("m_iTeamNum")
        self.m_vecOrigin = table.get_offset("m_vecOrigin")
        table = NetVarTable("DT_CSPlayer")
        self.m_hActiveWeapon = table.get_offset("m_hActiveWeapon")
        self.m_iShotsFired = table.get_offset("m_iShotsFired")
        self.m_iCrossHairID = table.get_offset("m_bHasDefuser") + 0x7C
        table = NetVarTable("DT_BaseAnimating")
        self.m_dwBoneMatrix = table.get_offset("m_nForceBone") + 0x2C
        table = NetVarTable("DT_BaseAttributableItem")
        self.m_iItemDefinitionIndex = table.get_offset("m_iItemDefinitionIndex")
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
        if g_glow:
            # 0x6A5C30 = hardcoded relocation end
            temp = mem.find_pattern(0x6A5C30, "client_client.so",
                b"\xE8\x00\x00\x00\x00\x48\x8B\x3D\x00\x00\x00\x00\xBE\x01\x00\x00\x00\xC7",
                "x????xxx????xxxxxx")
            temp = mem.read_absolute(temp, 1, 5)
            self.dwGlowObjectManager = mem.read_absolute(temp + 0x0B, 1, 5)
            self.dwGlowPointer = mem.read_i64(self.dwGlowObjectManager)


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
    if g_horizontal_only:
        sy = 0
    if g_current_tick - g_previous_tick > 0:
        g_previous_tick = g_current_tick
        mouse.move(int(sx), int(sy))


def get_crosshair_target(player):
    cross_id = player.get_cross_index()
    if cross_id == 0:
        return False
    cross_target = Entity.get_client_entity(cross_id)
    return player.get_team_num() != cross_target.get_team_num() and cross_target.get_health() > 0


if __name__ == "__main__":
    global mouse
    global mem
    global vt
    global nv
    global sensitivity
    global mp_teammates_are_enemies

    try:
        mouse = MouseInput()
        mem = Process("csgo_linux64")
        vt = InterfaceList()
        nv = NetVarList()
        _sensitivity = ConVar("sensitivity")
        mp_teammates_are_enemies = ConVar("mp_teammates_are_enemies")
    except Exception as e:
        print("Error: " + e.__str__())
        exit(0)

    print("[*]VirtualTables")
    print("    VClient:            " + hex(vt.client.table))
    print("    VClientEntityList:  " + hex(vt.entity.table))
    print("    VEngineClient:      " + hex(vt.engine.table))
    print("    VEngineCvar:        " + hex(vt.cvar.table))
    print("    InputSystemVersion: " + hex(vt.input.table))
    print("[*]Offsets")
    print("    EntityList:         " + hex(nv.entityList))
    print("    ClientState:        " + hex(nv.clientState))
    print("    GetLocalPlayer:     " + hex(nv.getLocalPlayer))
    print("    GetViewAngles:      " + hex(nv.dwViewAngles))
    print("    GetMaxClients:      " + hex(nv.dwMaxClients))
    print("    IsInGame:           " + hex(nv.dwState))
    print("[*]NetVars")
    print("    m_iHealth:          " + hex(nv.m_iHealth))
    print("    m_vecViewOffset:    " + hex(nv.m_vecViewOffset))
    print("    m_lifeState:        " + hex(nv.m_lifeState))
    print("    m_nTickBase:        " + hex(nv.m_nTickBase))
    print("    m_vecPunch:         " + hex(nv.m_vecPunch))
    print("    m_iTeamNum:         " + hex(nv.m_iTeamNum))
    print("    m_vecOrigin:        " + hex(nv.m_vecOrigin))
    print("    m_hActiveWeapon:    " + hex(nv.m_hActiveWeapon))
    print("    m_iShotsFired:      " + hex(nv.m_iShotsFired))
    print("    m_iCrossHairID:     " + hex(nv.m_iCrossHairID))
    print("    m_dwBoneMatrix:     " + hex(nv.m_dwBoneMatrix))
    print("[*]Info")
    print("    Creator:            github.com/ekknod")
    print("    Websites:           https://ekknod.xyz")
    while mem.exists() and not InputSystem.is_button_down(g_exit_key):
        libc.usleep(1000)
        if Engine.is_in_game():
            try:
                self = Entity.get_client_entity(Engine.get_local_player())
                fl_sensitivity = _sensitivity.get_float()
                view_angle = Engine.get_view_angles()
                if g_glow:
                    for i in range(0, mem.read_i32(nv.dwGlowObjectManager + 0x10)):
                        index = 0x40 * i
                        entity = Player(mem.read_i64(nv.dwGlowPointer + index))
                        if not entity.is_valid():
                            continue
                        if not mp_teammates_are_enemies.get_int() and self.get_team_num() == entity.get_team_num():
                            continue
                        entity_health = entity.get_health() / 100.0
                        mem.write_float(nv.dwGlowPointer + index + 0x08, 1.0 - entity_health)  # r
                        mem.write_float(nv.dwGlowPointer + index + 0x0C, entity_health)        # g
                        mem.write_float(nv.dwGlowPointer + index + 0x10, 1.0)                  # b
                        mem.write_float(nv.dwGlowPointer + index + 0x14, 0.5)                  # a
                        mem.write_i8(nv.dwGlowPointer + index + 0x28, 1)
                        mem.write_i8(nv.dwGlowPointer + index + 0x29, 0)
                if InputSystem.is_button_down(g_triggerbot_key) and get_crosshair_target(self):
                    mouse.click()
                if g_aimbot and InputSystem.is_button_down(g_aimbot_key):
                    g_current_tick = self.get_tick_count()
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
        else:
            g_previous_tick = 0
            target_set(Player(0))

