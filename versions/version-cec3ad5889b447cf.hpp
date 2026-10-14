#pragma once
/*            IDA dumper by theholytorch and nikky
Roblox Version:   version-cec3ad5889b447cf
Total Offsets:    176 */

#include <cstdint>
#include <string>

namespace Offsets {
    inline std::string ClientVersion = "0.742.0.7421053";

    namespace Luau {
        inline constexpr std::size_t BytecodeVerificationTableA = REBASE(0x83DE9B0);
        inline constexpr std::size_t CastArgs                   = REBASE(0x40ED3F0);
        inline constexpr std::size_t GcStep                     = REBASE(0x25B0210);
        inline constexpr std::size_t GetGlobalState             = REBASE(0x41921C0);
        inline constexpr std::size_t HClone                     = REBASE(0x25BED00);
        inline constexpr std::size_t KTable                     = REBASE(0x827B210);
        inline constexpr std::size_t LoadSafe                   = REBASE(0x25FFDD0);
        inline constexpr std::size_t LuaCStep                   = REBASE(0x25B0430);
        inline constexpr std::size_t LuaCheckStack              = REBASE(0x2587960);
        inline constexpr std::size_t LuaDThrow                  = REBASE(0x5772ED0);
        inline constexpr std::size_t LuaError                   = REBASE(0x258B520);
        inline constexpr std::size_t LuaGRunError               = REBASE(0x2591240);
        inline constexpr std::size_t LuaHDummyNode              = REBASE(0x6500E48);
        inline constexpr std::size_t LuaMNewGco                 = REBASE(0x25C9C60);
        inline constexpr std::size_t LuaNewState                = REBASE(0x258EFB0);
        inline constexpr std::size_t LuaONilObject              = REBASE(0x6504708);
        inline constexpr std::size_t LuaOPushFString            = REBASE(0x25C2C00);
        inline constexpr std::size_t LuaPushFString             = REBASE(0x25C3410);
        inline constexpr std::size_t LuaPushString              = REBASE(0x5B7A650);
        inline constexpr std::size_t LuaSetField                = REBASE(0x40E33D4);
        inline constexpr std::size_t LuaTTypeNames              = REBASE(0x6526340);
        inline constexpr std::size_t LuaVMLoad                  = REBASE(0x4188AF0);
        inline constexpr std::size_t LuauExecute                = REBASE(0x25CB0D0);
        inline constexpr std::size_t OpcodeLookUpTable          = REBASE(0x70F09C0);
        inline constexpr std::size_t Pseudo2Addr                = REBASE(0x25877C0);
        inline constexpr std::size_t RunError                   = REBASE(0x2591240);
        inline constexpr std::size_t TClone                     = REBASE(0x576A530);
        inline constexpr std::size_t print                      = REBASE(0x1C65A30);
    }

    namespace LuaB {
        inline constexpr std::size_t LuaBAssert       = REBASE(0x25EE450);
        inline constexpr std::size_t LuaBError        = REBASE(0x25E77B0);
        inline constexpr std::size_t LuaBGcinfo       = REBASE(0x25ECD90);
        inline constexpr std::size_t LuaBGetfenv      = REBASE(0x25E8DA0);
        inline constexpr std::size_t LuaBGetmetatable = REBASE(0x25E81F0);
        inline constexpr std::size_t LuaBNewproxy     = REBASE(0x25EF370);
        inline constexpr std::size_t LuaBNext         = REBASE(0x25ED9A0);
        inline constexpr std::size_t LuaBPrint        = REBASE(0x25E7350);
        inline constexpr std::size_t LuaBRawequal     = REBASE(0x25E9090);
        inline constexpr std::size_t LuaBRawget       = REBASE(0x25E91A0);
        inline constexpr std::size_t LuaBRawlen       = REBASE(0x25ECCF0);
        inline constexpr std::size_t LuaBRawset       = REBASE(0x25E9BC0);
        inline constexpr std::size_t LuaBSelect       = REBASE(0x25EE500);
        inline constexpr std::size_t LuaBSetfenv      = REBASE(0x25E8E60);
        inline constexpr std::size_t LuaBSetmetatable = REBASE(0x25E8380);
        inline constexpr std::size_t LuaBTonumber     = REBASE(0x25E7420);
        inline constexpr std::size_t LuaBTostring     = REBASE(0x25EF310);
        inline constexpr std::size_t LuaBType         = REBASE(0x25ECDB0);
        inline constexpr std::size_t LuaBTypeof       = REBASE(0x25ED3B0);
    }

    namespace LuaL {
        inline constexpr std::size_t LuaLCheckType    = REBASE(0x2590710);
        inline constexpr std::size_t LuaLGetMetafield = REBASE(0x25905A0);
    }

    namespace Capability {
        inline constexpr std::size_t CapabilityStruct = REBASE(0x30);
        inline constexpr std::size_t GetCapabilities  = REBASE(0x1CA23E0);
    }

    namespace ClassDescriptor {
        inline constexpr std::size_t GetPropertyData       = REBASE(0x1CA3D10);
        inline constexpr std::size_t GetPropertyDescriptor = REBASE(0x1CA05A0);
        inline constexpr std::size_t HashLookUp            = REBASE(0x29B8010);
    }

    namespace Coroutine {
        inline constexpr std::size_t CoroutineClose       = REBASE(0x578BBE0);
        inline constexpr std::size_t CoroutineCreate      = REBASE(0x578B250);
        inline constexpr std::size_t CoroutineFinally     = REBASE(0x578D1B0);
        inline constexpr std::size_t CoroutineIsyieldable = REBASE(0x578BB50);
        inline constexpr std::size_t CoroutineRunning     = REBASE(0x578BAE0);
        inline constexpr std::size_t CoroutineStatus      = REBASE(0x57897D0);
        inline constexpr std::size_t CoroutineWrap        = REBASE(0x578B810);
        inline constexpr std::size_t CoroutineYield       = REBASE(0x578BA80);
    }

    namespace EngineMisc {
        inline constexpr std::size_t ScriptContextResume = REBASE(0x423C6F0);
    }

    namespace Global {
        inline constexpr std::size_t GlobalAssert       = REBASE(0x25EE450);
        inline constexpr std::size_t GlobalError        = REBASE(0x25E77B0);
        inline constexpr std::size_t GlobalGcinfo       = REBASE(0x25ECD90);
        inline constexpr std::size_t GlobalGetFenv      = REBASE(0x25E8DA0);
        inline constexpr std::size_t GlobalGetmetatable = REBASE(0x25E81F0);
        inline constexpr std::size_t GlobalNewproxy     = REBASE(0x25EF370);
        inline constexpr std::size_t GlobalNext         = REBASE(0x25ED9A0);
        inline constexpr std::size_t GlobalPrint        = REBASE(0x25E7350);
        inline constexpr std::size_t GlobalRawequal     = REBASE(0x25E9090);
        inline constexpr std::size_t GlobalRawget       = REBASE(0x25E91A0);
        inline constexpr std::size_t GlobalRawlen       = REBASE(0x25ECCF0);
        inline constexpr std::size_t GlobalRawset       = REBASE(0x25E9BC0);
        inline constexpr std::size_t GlobalSelect       = REBASE(0x25EE500);
        inline constexpr std::size_t GlobalSetFenv      = REBASE(0x25E8E60);
        inline constexpr std::size_t GlobalSetmetatable = REBASE(0x25E8380);
        inline constexpr std::size_t GlobalTable        = REBASE(0x6526960);
        inline constexpr std::size_t GlobalTonumber     = REBASE(0x25E7420);
        inline constexpr std::size_t GlobalTostring     = REBASE(0x25EF310);
        inline constexpr std::size_t GlobalType         = REBASE(0x25ECDB0);
        inline constexpr std::size_t GlobalTypeof       = REBASE(0x25ED3B0);
    }

    namespace Instance {
        inline constexpr std::size_t FireProximityPrompt           = REBASE(0x30E9D90);
        inline constexpr std::size_t FireTouchInterest             = REBASE(0x9E22A0);
        inline constexpr std::size_t InstanceFindFirstAncestor     = REBASE(0x4E9D10);
        inline constexpr std::size_t InstanceFindFirstChild        = REBASE(0x4ED420);
        inline constexpr std::size_t InstanceFindFirstChildOfClass = REBASE(0x4E9FF0);
        inline constexpr std::size_t InstanceGetAttribute          = REBASE(0x47D50F0);
        inline constexpr std::size_t InstanceGetChildren           = REBASE(0x4EB030);
        inline constexpr std::size_t InstanceIndex                 = REBASE(0x4116650);
        inline constexpr std::size_t InstanceNew                   = REBASE(0x42AD470);
    }

    namespace Misc {
        inline constexpr std::size_t BooleanType                = REBASE(0x6E09978);
        inline constexpr std::size_t EnableLoadModule           = REBASE(0x869DBC8);
        inline constexpr std::size_t FFlagPointer               = REBASE(0x8A927F8);
        inline constexpr std::size_t GetFFlag                   = REBASE(0x4993490);
        inline constexpr std::size_t LockViolationInstanceCrash = REBASE(0x8749848);
        inline constexpr std::size_t LockViolationScriptCrash   = REBASE(0x869D9D8);
        inline constexpr std::size_t PrintIdentity              = REBASE(0x4243AB0);
        inline constexpr std::size_t SetFFlag                   = REBASE(0x498CE30);
    }

    namespace RakNet {
        inline constexpr std::size_t ConvertItemEnumToString = REBASE(0x47AFFC0);
        inline constexpr std::size_t HandleConnectionState   = REBASE(0x4762BF0);
        inline constexpr std::size_t ProcessNetworkPacket    = REBASE(0x27C5640);
        inline constexpr std::size_t RakPeerReceive          = REBASE(0x27B0A20);
        inline constexpr std::size_t RakPeerVirtualTable     = REBASE(0x6D03FC8);
        inline constexpr std::size_t Receive                 = REBASE(0x27DAEE0);
        inline constexpr std::size_t ReliabilityLayerSend    = REBASE(0x27DDA00);
        inline constexpr std::size_t ReportNetworkError      = REBASE(0x4750120);
        inline constexpr std::size_t Send                    = REBASE(0x27B9440);
        inline constexpr std::size_t SendPacketsToSelf       = REBASE(0x27AF010);
        inline constexpr std::size_t UpdateNetworkLoop       = REBASE(0x27AB230);
        inline constexpr std::size_t RakNetEncrypt           = REBASE(0x0); // not found
    }

    namespace Raycast {
        inline constexpr std::size_t BlockCast               = REBASE(0xD34110);
        inline constexpr std::size_t FastClusterEntityVTable = REBASE(0x6D70CE8);
        inline constexpr std::size_t ShapeCast               = REBASE(0xD348B0);
        inline constexpr std::size_t SphereCast              = REBASE(0xD34260);
        inline constexpr std::size_t WorldRootRaycast        = REBASE(0xD33140);
    }

    namespace RbxTransport {
        inline constexpr std::size_t AppDestructor                 = REBASE(0x20C8140);
        inline constexpr std::size_t AppReceive                    = REBASE(0x20C3420);
        inline constexpr std::size_t AppReceiveMaxBytes            = REBASE(0x20C3CD0);
        inline constexpr std::size_t AppRtti                       = REBASE(0x745E7E0);
        inline constexpr std::size_t AppSend                       = REBASE(0x20C3030);
        inline constexpr std::size_t AppVTable                     = REBASE(0x6CF6C38);
        inline constexpr std::size_t AppVtableSlots                = REBASE(0x1B);
        inline constexpr std::size_t ChannelCount                  = REBASE(0xE);
        inline constexpr std::size_t ClientAppConnection           = REBASE(0x890);
        inline constexpr std::size_t ClientChannelConfig           = REBASE(0x3A84FC0);
        inline constexpr std::size_t ClientChannelMask             = REBASE(0x880);
        inline constexpr std::size_t ClientDestructor              = REBASE(0x3A851C0);
        inline constexpr std::size_t ClientReceive                 = REBASE(0x3A858A0);
        inline constexpr std::size_t ClientRtti                    = REBASE(0x74FA7C8);
        inline constexpr std::size_t ClientSend                    = REBASE(0x3A852E0);
        inline constexpr std::size_t ClientVTable                  = REBASE(0x6D716E0);
        inline constexpr std::size_t FailureFallbackToRbxTransport = REBASE(0x86A3408);
        inline constexpr std::size_t GetConnectionErrorName        = REBASE(0x5239090);
        inline constexpr std::size_t ImageSize                     = REBASE(0x9130000);
        inline constexpr std::size_t ImageTimestamp                = REBASE(0xB43CFB4C);
        inline constexpr std::size_t ReceiveBatchSize              = REBASE(0x28);
        inline constexpr std::size_t ReceivedStreamSize            = REBASE(0x70);
        inline constexpr std::size_t SendResultSize                = REBASE(0x18);
        inline constexpr std::size_t StreamAppend                  = REBASE(0x20CA6B0);
        inline constexpr std::size_t StreamBytes                   = REBASE(0x18);
        inline constexpr std::size_t StreamCreate                  = REBASE(0x5237C70);
        inline constexpr std::size_t StreamDestroy                 = REBASE(0x208F860);
        inline constexpr std::size_t StreamInlineMode              = REBASE(0x38);
        inline constexpr std::size_t StreamLength                  = REBASE(0x20);
        inline constexpr std::size_t StreamPrefix                  = REBASE(0x40);
        inline constexpr std::size_t StreamSize                    = REBASE(0x58);
        inline constexpr std::size_t UseRbxTransportClient         = REBASE(0x8694E30);
    }

    namespace RemoteEvent {
        inline constexpr std::size_t FireAllClients = REBASE(0x3449AD0);
        inline constexpr std::size_t FireClient     = REBASE(0x3449880);
        inline constexpr std::size_t FireServer     = REBASE(0x34496E0);
        inline constexpr std::size_t InvokeClient   = REBASE(0x351D6D0);
        inline constexpr std::size_t InvokeServer   = REBASE(0x351D380);
    }

    namespace ScriptContext {
        inline constexpr std::size_t RequireBypass = REBASE(0x975);
    }

    namespace Sky {
        inline constexpr std::size_t CubeTextures = REBASE(0x2DF6870);
        inline constexpr std::size_t DrawCubeCall = REBASE(0x3747BC0);
        inline constexpr std::size_t DrawSkyEnv   = REBASE(0x3747BC0);
        inline constexpr std::size_t DrawSkyPixel = REBASE(0x3747BC0);
        inline constexpr std::size_t DrawStars    = REBASE(0x3747BC0);
        inline constexpr std::size_t DrawSun      = REBASE(0x3747BC0);
        inline constexpr std::size_t SkyGroup     = REBASE(0x7E1C7B8);
        inline constexpr std::size_t SkyThread    = REBASE(0x3744320);
    }

    namespace Task {
        inline constexpr std::size_t TaskCancel        = REBASE(0x4303CA0);
        inline constexpr std::size_t TaskDefer         = REBASE(0x4305390);
        inline constexpr std::size_t TaskDelay         = REBASE(0x4305C20);
        inline constexpr std::size_t TaskDesynchronize = REBASE(0x4304750);
        inline constexpr std::size_t TaskSpawn         = REBASE(0x4305880);
        inline constexpr std::size_t TaskSynchronize   = REBASE(0x43042E0);
        inline constexpr std::size_t TaskWait          = REBASE(0x4305F30);
    }

    namespace TaskScheduler {
        inline constexpr std::size_t TaskScheduler          = REBASE(0x8B79128);
        inline constexpr std::size_t TaskSchedulerTargetFPS = REBASE(0x83E7808);
    }

    namespace VTable {
        inline constexpr std::size_t vftFuncScriptSlot0   = REBASE(0x6DD78A0);
        inline constexpr std::size_t vftFuncScriptSlot1   = REBASE(0x6DD7A00);
        inline constexpr std::size_t vftMessageScriptSlot = REBASE(0x6DD7810);
        inline constexpr std::size_t vftNetworkStream     = REBASE(0x6CEB2D8);
        inline constexpr std::size_t vftWaitScriptSlot    = REBASE(0x6DD7660);
    }
}

