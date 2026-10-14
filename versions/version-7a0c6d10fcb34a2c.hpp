#pragma once
/*            IDA dumper by theholytorch and nikky
Roblox Version:   version-7a0c6d10fcb34a2c
Total Offsets:    177 */

#include <cstdint>
#include <string>

namespace Offsets {
    inline std::string ClientVersion = "0.743.0.7431129";

    namespace Luau {
        inline constexpr std::size_t BytecodeVerificationTableA = REBASE(0x85D1AB0);
        inline constexpr std::size_t CastArgs                   = REBASE(0x4100CF0);
        inline constexpr std::size_t GcStep                     = REBASE(0x2642940);
        inline constexpr std::size_t GetGlobalState             = REBASE(0x41AB690);
        inline constexpr std::size_t HClone                     = REBASE(0x2651850);
        inline constexpr std::size_t KTable                     = REBASE(0x84698A0);
        inline constexpr std::size_t LoadSafe                   = REBASE(0x269CFE0);
        inline constexpr std::size_t LuaCStep                   = REBASE(0x2642B60);
        inline constexpr std::size_t LuaCheckStack              = REBASE(0x2618190);
        inline constexpr std::size_t LuaDThrow                  = REBASE(0x58EAF90);
        inline constexpr std::size_t LuaError                   = REBASE(0x261BEA0);
        inline constexpr std::size_t LuaGRunError               = REBASE(0x2621B60);
        inline constexpr std::size_t LuaHDummyNode              = REBASE(0x667D2E8);
        inline constexpr std::size_t LuaMNewGco                 = REBASE(0x265C6B0);
        inline constexpr std::size_t LuaNewState                = REBASE(0x261F920);
        inline constexpr std::size_t LuaONilObject              = REBASE(0x667D848);
        inline constexpr std::size_t LuaOPushFString            = REBASE(0x2655760);
        inline constexpr std::size_t LuaPushFString             = REBASE(0x2655F70);
        inline constexpr std::size_t LuaPushString              = REBASE(0x5CE7900);
        inline constexpr std::size_t LuaSetField                = REBASE(0x40F6C81);
        inline constexpr std::size_t LuaTTypeNames              = REBASE(0x669EF70);
        inline constexpr std::size_t LuaVMLoad                  = REBASE(0x41A1EF0);
        inline constexpr std::size_t LuauExecute                = REBASE(0x265DB10);
        inline constexpr std::size_t OpcodeLookUpTable          = REBASE(0x72AC458);
        inline constexpr std::size_t Pseudo2Addr                = REBASE(0x2617FE0);
        inline constexpr std::size_t RunError                   = REBASE(0x2621B60);
        inline constexpr std::size_t TClone                     = REBASE(0x26929E0);
        inline constexpr std::size_t print                      = REBASE(0x1CE4150);
    }

    namespace LuaB {
        inline constexpr std::size_t LuaBAssert       = REBASE(0x26814B0);
        inline constexpr std::size_t LuaBError        = REBASE(0x2679F90);
        inline constexpr std::size_t LuaBGcinfo       = REBASE(0x267FDF0);
        inline constexpr std::size_t LuaBGetfenv      = REBASE(0x267B540);
        inline constexpr std::size_t LuaBGetmetatable = REBASE(0x267A9D0);
        inline constexpr std::size_t LuaBNewproxy     = REBASE(0x26823D0);
        inline constexpr std::size_t LuaBNext         = REBASE(0x2680A00);
        inline constexpr std::size_t LuaBPrint        = REBASE(0x2679B30);
        inline constexpr std::size_t LuaBRawequal     = REBASE(0x267B830);
        inline constexpr std::size_t LuaBRawget       = REBASE(0x267B940);
        inline constexpr std::size_t LuaBRawlen       = REBASE(0x267FD50);
        inline constexpr std::size_t LuaBRawset       = REBASE(0x267C7B0);
        inline constexpr std::size_t LuaBSelect       = REBASE(0x2681560);
        inline constexpr std::size_t LuaBSetfenv      = REBASE(0x267B600);
        inline constexpr std::size_t LuaBSetmetatable = REBASE(0x267AB60);
        inline constexpr std::size_t LuaBTonumber     = REBASE(0x2679C00);
        inline constexpr std::size_t LuaBTostring     = REBASE(0x2682370);
        inline constexpr std::size_t LuaBType         = REBASE(0x267FE10);
        inline constexpr std::size_t LuaBTypeof       = REBASE(0x2680410);
    }

    namespace LuaL {
        inline constexpr std::size_t LuaLCheckType    = REBASE(0x2621080);
        inline constexpr std::size_t LuaLGetMetafield = REBASE(0x2620F10);
    }

    namespace Capability {
        inline constexpr std::size_t CapabilityStruct = REBASE(0x30);
        inline constexpr std::size_t GetCapabilities  = REBASE(0x1D22A20);
    }

    namespace ClassDescriptor {
        inline constexpr std::size_t GetPropertyData       = REBASE(0x1D24490);
        inline constexpr std::size_t GetPropertyDescriptor = REBASE(0x1D20C00);
        inline constexpr std::size_t HashLookUp            = REBASE(0x2A5C4D0);
    }

    namespace Coroutine {
        inline constexpr std::size_t CoroutineClose       = REBASE(0x5903F10);
        inline constexpr std::size_t CoroutineCreate      = REBASE(0x5903580);
        inline constexpr std::size_t CoroutineFinally     = REBASE(0x59054D0);
        inline constexpr std::size_t CoroutineIsyieldable = REBASE(0x5903E80);
        inline constexpr std::size_t CoroutineRunning     = REBASE(0x5903E10);
        inline constexpr std::size_t CoroutineStatus      = REBASE(0x5901B10);
        inline constexpr std::size_t CoroutineWrap        = REBASE(0x5903B40);
        inline constexpr std::size_t CoroutineYield       = REBASE(0x5903DB0);
    }

    namespace EngineMisc {
        inline constexpr std::size_t ScriptContextResume = REBASE(0x4256C10);
    }

    namespace Global {
        inline constexpr std::size_t GlobalAssert       = REBASE(0x26814B0);
        inline constexpr std::size_t GlobalError        = REBASE(0x2679F90);
        inline constexpr std::size_t GlobalGcinfo       = REBASE(0x267FDF0);
        inline constexpr std::size_t GlobalGetFenv      = REBASE(0x267B540);
        inline constexpr std::size_t GlobalGetmetatable = REBASE(0x267A9D0);
        inline constexpr std::size_t GlobalNewproxy     = REBASE(0x26823D0);
        inline constexpr std::size_t GlobalNext         = REBASE(0x2680A00);
        inline constexpr std::size_t GlobalPrint        = REBASE(0x2679B30);
        inline constexpr std::size_t GlobalRawequal     = REBASE(0x267B830);
        inline constexpr std::size_t GlobalRawget       = REBASE(0x267B940);
        inline constexpr std::size_t GlobalRawlen       = REBASE(0x267FD50);
        inline constexpr std::size_t GlobalRawset       = REBASE(0x267C7B0);
        inline constexpr std::size_t GlobalSelect       = REBASE(0x2681560);
        inline constexpr std::size_t GlobalSetFenv      = REBASE(0x267B600);
        inline constexpr std::size_t GlobalSetmetatable = REBASE(0x267AB60);
        inline constexpr std::size_t GlobalTable        = REBASE(0x669F590);
        inline constexpr std::size_t GlobalTonumber     = REBASE(0x2679C00);
        inline constexpr std::size_t GlobalTostring     = REBASE(0x2682370);
        inline constexpr std::size_t GlobalType         = REBASE(0x267FE10);
        inline constexpr std::size_t GlobalTypeof       = REBASE(0x2680410);
    }

    namespace Instance {
        inline constexpr std::size_t FireProximityPrompt           = REBASE(0x30CFF60);
        inline constexpr std::size_t FireTouchInterest             = REBASE(0xA08F20);
        inline constexpr std::size_t InstanceFindFirstAncestor     = REBASE(0x4FA2D0);
        inline constexpr std::size_t InstanceFindFirstChild        = REBASE(0x4FD9E0);
        inline constexpr std::size_t InstanceFindFirstChildOfClass = REBASE(0x4FA5B0);
        inline constexpr std::size_t InstanceGetAttribute          = REBASE(0x483C750);
        inline constexpr std::size_t InstanceGetChildren           = REBASE(0x4FB5F0);
        inline constexpr std::size_t InstanceIndex                 = REBASE(0x412A0B0);
        inline constexpr std::size_t InstanceNew                   = REBASE(0x42C9000);
    }

    namespace Misc {
        inline constexpr std::size_t BooleanType                = REBASE(0x6FC42D8);
        inline constexpr std::size_t EnableLoadModule           = REBASE(0x888F650);
        inline constexpr std::size_t FFlagPointer               = REBASE(0x8C86398);
        inline constexpr std::size_t GetFFlag                   = REBASE(0x49FE870);
        inline constexpr std::size_t LockViolationInstanceCrash = REBASE(0x893C6E8);
        inline constexpr std::size_t LockViolationScriptCrash   = REBASE(0x888F4A8);
        inline constexpr std::size_t PrintIdentity              = REBASE(0x425DFF0);
        inline constexpr std::size_t SetFFlag                   = REBASE(0x49F6B50);
    }

    namespace RakNet {
        inline constexpr std::size_t ConvertItemEnumToString = REBASE(0x48187F0);
        inline constexpr std::size_t HandleConnectionState   = REBASE(0x47CA3E0);
        inline constexpr std::size_t ProcessNetworkPacket    = REBASE(0x28667A0);
        inline constexpr std::size_t RakNetEncrypt           = REBASE(0x28834F0);
        inline constexpr std::size_t RakPeerReceive          = REBASE(0x28519B0);
        inline constexpr std::size_t RakPeerVirtualTable     = REBASE(0x6EBEC40);
        inline constexpr std::size_t Receive                 = REBASE(0x287D470);
        inline constexpr std::size_t ReliabilityLayerSend    = REBASE(0x287FF90);
        inline constexpr std::size_t ReportNetworkError      = REBASE(0x47B69F0);
        inline constexpr std::size_t Send                    = REBASE(0x285A3D0);
        inline constexpr std::size_t SendPacketsToSelf       = REBASE(0x284FFA0);
        inline constexpr std::size_t UpdateNetworkLoop       = REBASE(0x28503B0);
    }

    namespace Raycast {
        inline constexpr std::size_t BlockCast               = REBASE(0xD5DCD0);
        inline constexpr std::size_t FastClusterEntityVTable = REBASE(0x6F2A0F0);
        inline constexpr std::size_t ShapeCast               = REBASE(0xD5E470);
        inline constexpr std::size_t SphereCast              = REBASE(0xD5DE20);
        inline constexpr std::size_t WorldRootRaycast        = REBASE(0xD5C460);
    }

    namespace RbxTransport {
        inline constexpr std::size_t AppDestructor                 = REBASE(0x21547F0);
        inline constexpr std::size_t AppReceive                    = REBASE(0x214F490);
        inline constexpr std::size_t AppReceiveMaxBytes            = REBASE(0x214FD40);
        inline constexpr std::size_t AppRtti                       = REBASE(0x7629560);
        inline constexpr std::size_t AppSend                       = REBASE(0x214F0A0);
        inline constexpr std::size_t AppVTable                     = REBASE(0x6EB18C0);
        inline constexpr std::size_t AppVtableSlots                = REBASE(0x1C);
        inline constexpr std::size_t ChannelCount                  = REBASE(0xE);
        inline constexpr std::size_t ClientAppConnection           = REBASE(0x890);
        inline constexpr std::size_t ClientChannelConfig           = REBASE(0x3A85330);
        inline constexpr std::size_t ClientChannelMask             = REBASE(0x880);
        inline constexpr std::size_t ClientDestructor              = REBASE(0x3A85530);
        inline constexpr std::size_t ClientReceive                 = REBASE(0x3A85C10);
        inline constexpr std::size_t ClientRtti                    = REBASE(0x76C38D0);
        inline constexpr std::size_t ClientSend                    = REBASE(0x3A85650);
        inline constexpr std::size_t ClientVTable                  = REBASE(0x6F2ACB0);
        inline constexpr std::size_t FailureFallbackToRbxTransport = REBASE(0x88961B8);
        inline constexpr std::size_t GetConnectionErrorName        = REBASE(0x52CFF20);
        inline constexpr std::size_t ImageSize                     = REBASE(0x9658000);
        inline constexpr std::size_t ImageTimestamp                = REBASE(0xFB09251C);
        inline constexpr std::size_t ReceiveBatchSize              = REBASE(0x28);
        inline constexpr std::size_t ReceivedStreamSize            = REBASE(0x70);
        inline constexpr std::size_t SendResultSize                = REBASE(0x18);
        inline constexpr std::size_t StreamAppend                  = REBASE(0x2156D80);
        inline constexpr std::size_t StreamBytes                   = REBASE(0x18);
        inline constexpr std::size_t StreamCreate                  = REBASE(0x52CE7D0);
        inline constexpr std::size_t StreamDestroy                 = REBASE(0x211A420);
        inline constexpr std::size_t StreamInlineMode              = REBASE(0x38);
        inline constexpr std::size_t StreamLength                  = REBASE(0x20);
        inline constexpr std::size_t StreamPrefix                  = REBASE(0x40);
        inline constexpr std::size_t StreamSize                    = REBASE(0x58);
        inline constexpr std::size_t UseRbxTransportClient         = REBASE(0x88877D8);
    }

    namespace RemoteEvent {
        inline constexpr std::size_t FireAllClients = REBASE(0x3448850);
        inline constexpr std::size_t FireClient     = REBASE(0x3448600);
        inline constexpr std::size_t FireServer     = REBASE(0x3448460);
        inline constexpr std::size_t InvokeClient   = REBASE(0x351E630);
        inline constexpr std::size_t InvokeServer   = REBASE(0x351E2E0);
    }

    namespace ScriptContext {
        inline constexpr std::size_t RequireBypass = REBASE(0xA81);
    }

    namespace Sky {
        inline constexpr std::size_t CubeTextures = REBASE(0x374BCA0);
        inline constexpr std::size_t DrawCubeCall = REBASE(0x374F7B0);
        inline constexpr std::size_t DrawSkyEnv   = REBASE(0x374F7B0);
        inline constexpr std::size_t DrawSkyPixel = REBASE(0x374F7B0);
        inline constexpr std::size_t DrawStars    = REBASE(0x374F7B0);
        inline constexpr std::size_t DrawSun      = REBASE(0x374F7B0);
        inline constexpr std::size_t SkyGroup     = REBASE(0x8002008);
        inline constexpr std::size_t SkyThread    = REBASE(0x374BF40);
    }

    namespace Task {
        inline constexpr std::size_t TaskCancel        = REBASE(0x4321040);
        inline constexpr std::size_t TaskDefer         = REBASE(0x4322730);
        inline constexpr std::size_t TaskDelay         = REBASE(0x4322FB0);
        inline constexpr std::size_t TaskDesynchronize = REBASE(0x4321AF0);
        inline constexpr std::size_t TaskSpawn         = REBASE(0x4322C10);
        inline constexpr std::size_t TaskSynchronize   = REBASE(0x4321680);
        inline constexpr std::size_t TaskWait          = REBASE(0x43232B0);
    }

    namespace TaskScheduler {
        inline constexpr std::size_t TaskScheduler          = REBASE(0x8D6F048);
        inline constexpr std::size_t TaskSchedulerTargetFPS = REBASE(0x85DAA10);
    }

    namespace VTable {
        inline constexpr std::size_t vftFuncScriptSlot0   = REBASE(0x6F922A0);
        inline constexpr std::size_t vftFuncScriptSlot1   = REBASE(0x6F92180);
        inline constexpr std::size_t vftMessageScriptSlot = REBASE(0x6F92010);
        inline constexpr std::size_t vftNetworkStream     = REBASE(0x6EA5F00);
        inline constexpr std::size_t vftWaitScriptSlot    = REBASE(0x6F91E60);
    }
}

