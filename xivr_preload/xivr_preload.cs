using System;
using System.Diagnostics;
using Dalamud;
using Dalamud.Logging;
using Dalamud.Plugin;
using Dalamud.Interface;
using Dalamud.Hooking;
using Dalamud.Utility.Signatures;

namespace xivr_preload
{
    public unsafe class xivr_preload : IDalamudPlugin
    {
        public static xivr_preload Plugin { get; private set; }
        public string Name => "xivr_preload";
        public static Configuration cfg { get; private set; }

        private readonly bool pluginReady = false;

        private GUID IID_IDXGIFactory = new GUID(0x7b7166ec, 0x21c7, 0x44ae, 0xb2, 0x1a, 0xc9, 0xae, 0x32, 0x1a, 0xe3, 0x69);
        private GUID IID_IDXGIFactory1 = new GUID(0x770aae78, 0xf26f, 0x4dba, 0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87);
        private GUID IID_IDXGIFactory2 = new GUID(0x50c83a1c, 0xe072, 0x4c48, 0x87, 0xb0, 0x36, 0x30, 0xfa, 0x36, 0xa6, 0xd0);
        private struct GUID
        {
            uint v1;
            ushort v2;
            ushort v3;
            byte v4;
            byte v5;
            byte v6;
            byte v7;
            byte v8;
            byte v9;
            byte vA;
            byte vB;

            public GUID(uint n1, ushort n2, ushort n3, byte n4, byte n5, byte n6, byte n7, byte n8, byte n9, byte nA, byte nB)
            {
                v1 = n1;
                v2 = n2;
                v3 = n3;
                v4 = n4;
                v5 = n5;
                v6 = n6;
                v7 = n7;
                v8 = n8;
                v9 = n9;
                vA = nA;
                vB = nB;
            }
        }

        private static class Signatures
        {
            internal const string CreateDXGIFactory = "E8 ?? ?? ?? ?? 85 C0 0F 88 ?? ?? ?? ?? 48 8B 8F 28 02 00 00";
        }

        public unsafe xivr_preload(DalamudPluginInterface pluginInterface)
        {
            Plugin = this;
            cfg = pluginInterface.GetPluginConfig() as Configuration ?? new Configuration();
            cfg.Initialize(pluginInterface);

            try
            {
                SignatureHelper.Initialise(this);
                CreateDXGIFactoryStatus(true);
                pluginReady = true;
            }
            catch (Exception e) { PluginLog.LogError($"Failed loading plugin\n{e}"); }
        }

        public void Dispose()
        {
            if (pluginReady)
            {
                CreateDXGIFactoryStatus(false);
            }
        }

        //----
        // CreateDXGIFactory
        //----
        private delegate UInt64 CreateDXGIFactoryDg(GUID* a, UInt64 b);
        [Signature(Signatures.CreateDXGIFactory, DetourName = nameof(CreateDXGIFactoryFn))]
        private Hook<CreateDXGIFactoryDg>? CreateDXGIFactoryHook = null;

        private delegate UInt64 CreateDXGIFactory1Dg(GUID* a, UInt64 b);
        private Hook<CreateDXGIFactory1Dg>? CreateDXGIFactory1Hook = null;

        private delegate UInt64 CreateDXGIFactory2Dg(GUID* a, UInt64 b);
        private Hook<CreateDXGIFactory2Dg>? CreateDXGIFactory2Hook = null;

        private void CreateDXGIFactoryStatus(bool status)
        {
            //----
            // CreateDXGIFactory1 is 0x1A0 bytes after CreateDXGIFactory
            // CreateDXGIFactory2 is 0xA0 bytes after CreateDXGIFactory
            // Should remain stable until DirectX updates
            //----
            if (status == true)
            {
                CreateDXGIFactoryHook?.Enable();
                IntPtr CreateDXGIFactory2 = CreateDXGIFactoryHook!.Address + 0xA0;
                CreateDXGIFactory2Hook = Hook<CreateDXGIFactory2Dg>.FromAddress(CreateDXGIFactory2, CreateDXGIFactory2Fn);
                IntPtr CreateDXGIFactory1 = CreateDXGIFactoryHook!.Address + 0x1A0;
                CreateDXGIFactory1Hook = Hook<CreateDXGIFactory1Dg>.FromAddress(CreateDXGIFactory1, CreateDXGIFactory1Fn);
            }
            else
            {
                CreateDXGIFactory1Hook?.Disable();
                CreateDXGIFactory2Hook?.Disable();
                CreateDXGIFactoryHook?.Disable();
            }
        }

        private unsafe UInt64 CreateDXGIFactoryFn(GUID* a, UInt64 b)
        {
            UInt64 retVal = 0;
            fixed (GUID* ptrGUI = &IID_IDXGIFactory1)
                retVal = CreateDXGIFactory1Hook!.Original(ptrGUI, b);
            PluginLog.Log($"CreateDXGIFactory Redirected to CreateDXGIFactory1 : {retVal}");
            return retVal;
            //return CreateDXGIFactoryHook!.Original(a, b);
        }

        private UInt64 CreateDXGIFactory1Fn(GUID* a, UInt64 b)
        {
            return CreateDXGIFactory1Hook!.Original(a, b);
        }
        private UInt64 CreateDXGIFactory2Fn(GUID* a, UInt64 b)
        {
            return CreateDXGIFactory2Hook!.Original(a, b);
        }
    }
}