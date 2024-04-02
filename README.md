# AFL Fuzzing Project :bug:

## Overview :mag_right:

This project explores the application of AFL (American Fuzzy Lop) fuzzing on three widely used binaries: OpenSSL (Heartbleed bug), TCPDUMP, and VIM. Our goal was to uncover vulnerabilities, with a special focus on the infamous Heartbleed bug in OpenSSL, and to assess the robustness of TCPDUMP and VIM against malformed inputs.

## Fuzzing TCPDUMP :satellite:

- **Summary**: Focused on the TCPDUMP tool, which captures and analyzes network packets. Aimed to find vulnerabilities that could be exploited.
- **Execution**: Launched AFL++ with specific configurations and seed files to explore the behavior of TCPDUMP under unexpected inputs.
- **Results**: Uncovered a crash due to a buffer over-read vulnerability in the BOOTP parser, which was previously reported and patched (CVE-2017-13028).
### What is TCP Dump:
TCPdump is a command-line tool that captures network packets from a specified network interface or file and displays the packet details on the terminal. It can capture packets that match specific criteria, such as source or destination IP addresses, port numbers, and protocol types. TCPdump provides real-time packet capture and analysis capabilities, making it a valuable tool for various network-related tasks.

### AFL CMD Used 
```
[AFL++ 44d37eb15308] /src/tcpdump-tcpdump-4.9.2 # afl-fuzz -m none -i /src/tcpdump-tcpdump-4.9.2/tests/ -o /src/tcpdump-tcpdump-4.9.2/out/ -s 123 -- /src/tcpdump-tcpdump-4.9.2/install/sbin/tcpdump -vvvvXX -ee -nn -r @@
```

**Initial Seed Input**
The list of seed file is the pcap from the test folder of tcpdump repository.

**![](https://lh7-us.googleusercontent.com/EONTsG3_XVxvhVcE-twsci9O6g0KlOcIRVWaB9MO45PFmubH2BQXltcGqjvlR_4j98mLHLS8yWEprIckYEXM8Caug8IVAU0xSBPm2yX17tOn5gGg-74enbnFXB5UYSm1-IDHQgrBlrkU6_uvCWvO7aE)**

**Crash And AFL++ Output**

**![](https://lh7-us.googleusercontent.com/WZlsg0AhldOsNdFpsWDiOwIYXgjcxQg20oPhPwIzG01ZtVCf96Vo4YVQy46jREHLxUFXtRlXV8RQMBiEkwCU1CQ2akIHM9Ej79FqP45PhvFnDoOZcREj8wzSFK6oZIXw61_aQ8hjwDhgWdlHvcP9i90)**

**Crash Files**

**![](https://lh7-us.googleusercontent.com/J4Zqkv2rChB0rXEdClekoO18NuNG43x8I9gTIpRg6ZN8QnCQOi83ye7XPA47hq541K6Q5jipUJ_bB894xzNHXjjsWSwjp5cALl92J3dgS29yW0lb-YMLLNTIfGdUyxWHwWjDXLpDhcqijyIN1dwXoJ4)**
### Checking Crash Input 
**Executing the crash Input**
`**./install/sbin/tcpdump -vvvvXX -ee -nn -r ./out/default/crashes/id:000000,sig:11,src:000612,time:1830,execs:3956,op:havoc,rep:3**`

### Observation
**As Expected Binary Crashed**
**![](https://lh7-us.googleusercontent.com/DWwepJLdBzzVBQhmKaEgRePCmMaNzwAcPQnnCpJNx_8qdRp7q7wG1zuRcKglkn-Dip9wo6UzXyAIgdkf5XblXuon3tgOWhksChj6ux665WBvh3y0oW4TvMMXWzFZ9JU_PdnXWKTZ68xTQdyHvhkQcVI)**
### Explanation of Crash [Detailed]


The main exploit is The BOOTP parser in tcpdump before 4.9.2 has a buffer over-read in `print-bootp.c:bootp_print()`.

Problem is in a program called tcpdump, which is used to look at data that travels over computer networks. The issue affects versions of tcpdump released before version 4.9.2. The part of tcpdump that's causing trouble is the part that deals with a network protocol called BOOTP, which helps computers get important network settings when they start up.

In this case, there's a problem with how tcpdump reads and shows information from BOOTP packets. Think of these packets as envelopes with data inside. The issue is like someone trying to read outside the edges of an envelope. When that happens, it can cause problems like the program crashing or revealing secret information from the computer's memory.

If a adversary exploits this issue, they could make tcpdump misunderstand network data. This could lead to problems like crashes, information leaks, or even a complete takeover of the computer, which is very serious. To stay safe, it's important to use a newer version of tcpdump, like 4.9.2 or later, where they've fixed this problem which is explained in next page..

A diagram explaining how the path flow changes from normal to undefined behavior


**![](https://lh7-us.googleusercontent.com/v2Yne-rZUOrZEFdLWFtcDSbqLW5YGBB2yLDceiaJFsz0eI6XIT5JnX6sbfYgGsQybpOePMfyVYb79QKK9x_z-LmNi7gNgD0VPzBOnQ-vch2_DVHEab35Z3NM73FSYTROVzH3_o5qvhVN4T4hX-A7PFg)**
### Proposed Fix

To fix this issue in the code base of  `print-bootp.c`  the check was address for buffer over read.
In this context, `"ND_TCHECK"` is likely a macro or function used to perform a bounds check on the `"bp_flags"` field within the BOOTP packet. The purpose of a bounds check is to ensure that the program doesn't read or access data beyond the boundaries of the specific field or buffer in memory. This check is essential for preventing buffer over-read vulnerabilities.
By adding the line `"ND_TCHECK(bp->bp_flags);"` to the code, the developers are taking steps to make sure that the program doesn't accidentally read data outside of the `"bp_flags"` field's allocated memory space. This kind of check can help prevent buffer over-read vulnerabilities and enhance the security of the program.

**![](https://lh7-us.googleusercontent.com/w0cO8S-Q_hThI5ADXFRwljTfxhu4egOgQ3b55fueqfJvdtYxNM7FzyjU_XmZFwsg9tiYXbcX8CdVszEJ7xT4ODBAHbcJ3ZrlOPFqSNSZf07hlCAI43CKPnfAYY4S8_VVUB6QS2GMghPFh5LZXnJ9fnw)**

This bug is already reported to the developer and yes this bug was exploitable and a CVE was created CVE-2017-13028 [1]

And the fix was propose and can be validate in the following git commit[2] where the put a check on the value.

Impact of this vulnerability was  A remote attacker could possibly execute arbitrary code with the privileges of the process or cause a Denial of Service condition.[3]



## VIM Fuzzing Attempt :memo:

- **Approach**: Attempted to fuzz the VIM editor to identify any unknown vulnerabilities.
- **Outcome**: After 2 hours of intensive fuzzing, no crashes were found, indicating VIM's resilience to the tested malformed inputs.
- CMD Used: `afl-fuzz -m none -i corpus -o output ./vim -u NONE -X -Z -e -s -S @@ -c ':qa!'`

**AFL VIM Dashboard**


**![](https://lh7-us.googleusercontent.com/fqKBFysiXoYikB9cX3v8M_cIKo-L0fCoX6MJUiMo3479eohEJMb6GRvqSL6tvq2CUnxfoMzeo0SiJK27gY71nJgY0XC0Tf4eWIoInoMAx7m0UnXgKHTD0a6wb5Upzl5C-uBuatvQWtFzB19FsY6b_Xc)**

## Key Takeaways :bulb:

- **Early Integration**: Incorporating fuzzing into the early stages of development can significantly enhance software security.
- **Continuous Testing**: Continuous fuzzing is essential for maintaining the integrity of widely used software.
- **Community Contribution**: Reporting vulnerabilities and contributing to their resolution is crucial for the cybersecurity ecosystem.
## Heartbleed Bug in OpenSSL :heart:

- **Summary**: Discovered a serious vulnerability in the OpenSSL cryptographic software library, allowing theft of information that should be protected by SSL/TLS encryption.
- **Methodology**: Configured a basic SSL/TLS server to simulate incoming connections and applied AFL fuzzing with code instrumentation for thorough testing.
- **Findings**: Demonstrated how AFL could have identified the Heartbleed bug during the development phase, potentially preventing its widespread impact.

## Report

### Description
The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. This weakness allows stealing the information protected, under normal conditions, by the SSL/TLS encryption. 

The Heartbleed bug allows anyone on the Internet to read the memory of the systems protected by the vulnerable versions of the OpenSSL software. This compromises the secret keys used to identify the service providers and to encrypt the traffic, the names and passwords of the users and the actual content. This allows attackers to eavesdrop on communications, steal data directly from the services and users and to impersonate services and users. [5]

**AFL Heart Bleed Dashboard**

**![](https://lh7-us.googleusercontent.com/10Co0SANN0O_RBT2lMn4JU9I_KGY-djMzyv96Z5ha7o65sHXeIvXkYiovHocxsj3fHzObLHAi_CWi9WD-dwLezoGDvWTtbGZ2JEG5RV6QOoSMlu_yBRF931IjfOQxZNgwo2HAF90LNPSzOkW_DugtN0)**
**Inputs that lead to the Crash** 

**![](https://lh7-us.googleusercontent.com/Gls5DxOwqxAEuBr59S8xr9EhcVM-Y3h-3AEYfB0Dw4Dd-4B8jzSUBUkXLft5PSud-AImu95yPDukbaqJ_UlQ8FQVRjuUf_yPnbzQR8BcbLYYvqRUEt75l6_VFnH-LcuXT2n16ZtMfelLiWYG6IKvsXU)**
## Gallery :framed_picture:

Included are screenshots from our fuzzing sessions, showcasing the AFL interface, crash inputs, and the steps to reproduce the findings.

## Acknowledgements :clap:

Special thanks to the AFL community for providing the tools and resources that made this project possible.

---

Proudly fuzzed with :heart: and AFL.

## Citations
[1] https://www.cvedetails.com/cve/CVE-2017-13028/

[2] [https://github.com/the-tcpdump-group/tcpdump/commit/29e5470e6ab84badbc31f4532bb7554a796d9d52](https://github.com/the-tcpdump-group/tcpdump/commit/29e5470e6ab84badbc31f4532bb7554a796d9d52)

[3] [https://security.gentoo.org/glsa/201709-23](https://security.gentoo.org/glsa/201709-23)

[4] [Fuzzing101 with LibAFL - Part III: Fuzzing tcpdump (epi052.gitlab.io)](https://epi052.gitlab.io/notes-to-self/blog/2021-11-20-fuzzing-101-with-libafl-part-3/)

[5] https://heartbleed.com/
