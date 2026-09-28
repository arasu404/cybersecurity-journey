# Shadow Gate — Null CTF

![Category](https://img.shields.io/badge/Category-PWN-red)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green)
![Points](https://img.shields.io/badge/Points-100-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-black)
![Architecture](https://img.shields.io/badge/Architecture-x86__64-purple)

> A classified security terminal has been discovered on an abandoned network.
> The system requires an authorization code - but the authentication logic seems flawed.
> Can you breach the Shadow Gate?

---

## Table of Contents

- [Challenge Information](#challenge-information)
- [Challenge Description](#challenge-description)
- [Objective](#objective)
- [Environment](#environment)
- [1. Obtaining the Binary](#1-obtaining-the-binary)
- [2. Initial Binary Identification](#2-initial-binary-identification)
- [3. Checking Symbols](#3-checking-symbols)
- [4. Searching for Interesting Strings](#4-searching-for-interesting-strings)
- [5. Checking Binary Protections](#5-checking-binary-protections)
- [6. Understanding the Challenge](#6-understanding-the-challenge)
- [7. Finding the Hidden Function](#7-finding-the-hidden-function)
- [8. Understanding the Hidden Function](#8-understanding-the-hidden-function)
- [9. Finding the Vulnerable Function](#9-finding-the-vulnerable-function)
- [10. Identifying the Buffer Overflow](#10-identifying-the-buffer-overflow)
- [11. Calculating the RIP Offset](#11-calculating-the-rip-offset)
- [12. Finding the ROP Gadget](#12-finding-the-rop-gadget)
- [13. Understanding the Calling Convention](#13-understanding-the-calling-convention)
- [14. Building the ROP Chain](#14-building-the-rop-chain)
- [15. Understanding the Final Payload](#15-understanding-the-final-payload)
- [16. Creating the Initial Exploit](#16-creating-the-initial-exploit)
- [17. Local Testing](#17-local-testing)
- [18. GDB Verification](#18-gdb-verification)
- [19. Testing the Remote Service](#19-testing-the-remote-service)
- [20. Debugging the Remote ROP Chain](#20-debugging-the-remote-rop-chain)
- [21. Stack Alignment](#21-stack-alignment)
- [22. Final Exploit](#22-final-exploit)
- [23. Getting the Flag](#23-getting-the-flag)
- [24. Complete Technical Analysis](#24-complete-technical-analysis)
- [25. Vulnerability Root Cause](#25-vulnerability-root-cause)
- [26. Exploitation Flow](#26-exploitation-flow)
- [27. Important Concepts Learned](#27-important-concepts-learned)
- [28. Useful Commands](#28-useful-commands)
- [29. Final Exploit Code](#29-final-exploit-code)
- [30. Flag](#30-flag)
- [Conclusion](#conclusion)

---

# Challenge Information

| Field | Information |
|---|---|
| **CTF** | Null CTF |
| **Challenge** | Shadow Gate |
| **Category** | PWN / Binary Exploitation |
| **Difficulty** | Easy |
| **Points** | 100 |
| **Architecture** | x86-64 |
| **Binary** | `shadow_gate` |
| **Remote Host** | `141.148.200.229` |
| **Remote Port** | `9001` |
| **Technique** | Stack Buffer Overflow + ROP |

---

# Challenge Description

The challenge provides a binary named:

```text
shadow_gate
