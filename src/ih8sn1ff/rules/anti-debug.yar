rule AntiDebug_Common_APIs
{
    meta:
        description = "Common debugger-detection APIs"
        author = "ih8sn1ff"
    strings:
        $a0 = "IsDebuggerPresent" ascii
        $a1 = "CheckRemoteDebuggerPresent" ascii
        $a2 = "NtQueryInformationProcess" ascii
        $a3 = "OutputDebugStringA" ascii
    condition:
        2 of them
}

rule AntiDebug_Timing_APIs
{
    meta:
        description = "Timing checks used for debugger detection"
        author = "ih8sn1ff"
    strings:
        $t0 = "QueryPerformanceCounter" ascii
        $t1 = "GetTickCount64" ascii
        $t2 = "timeGetTime" ascii
    condition:
        2 of them
}

rule AntiVM_Markers
{
    meta:
        description = "Virtual machine / sandbox markers"
        author = "ih8sn1ff"
    strings:
        $v0 = "VBoxService" ascii
        $v1 = "VBoxTray" ascii
        $v2 = "VMware Tools" ascii
        $v3 = "SbieDll.dll" ascii nocase
        $v4 = "sandboxie" ascii nocase
    condition:
        any of them
}
