rule Packer_VMProtect_Sections
{
    meta:
        description = "VMProtect section markers"
        author = "ih8sn1ff"
    strings:
        $v0 = ".vmp0" ascii
        $v1 = ".vmp1" ascii
        $v2 = ".vmp2" ascii
    condition:
        any of them
}

rule Packer_Themida_WinLicense
{
    meta:
        description = "Themida / WinLicense section markers"
        author = "ih8sn1ff"
    strings:
        $t0 = ".themida" ascii nocase
        $t1 = ".winlice" ascii nocase
        $t2 = "Themida" ascii
    condition:
        any of them
}

rule Packer_UPX
{
    meta:
        description = "UPX packer markers"
        author = "ih8sn1ff"
    strings:
        $u0 = "UPX0" ascii
        $u1 = "UPX1" ascii
        $u2 = "UPX!" ascii
    condition:
        2 of them
}

rule Packer_Enigma
{
    meta:
        description = "Enigma Protector section markers"
        author = "ih8sn1ff"
    strings:
        $e0 = ".enigma1" ascii nocase
        $e1 = ".enigma2" ascii nocase
    condition:
        any of them
}

rule DotNet_Reactor
{
    meta:
        description = ".NET Reactor / Eziriz markers"
        author = "ih8sn1ff"
    strings:
        $n0 = ".NET Reactor" ascii nocase
        $n1 = "Eziriz" ascii nocase
    condition:
        any of them
}
