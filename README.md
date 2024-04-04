# Password Manager User Guide

This file provides a simple guide for using the Cryptic Password Manager command-line program. The program allows users to securely store and manage passwords for different accounts or services.

## Table of Contents

- [Getting Started](#getting-started)
- [Commands](#commands)
  - [Add Account](#add-account)
  - [List Accounts](#list-accounts)
  - [Remove Account](#remove-account)
  - [Generate Password](#generate-password)
  - [Update Password](#update-password)
- [Master Password](#master-password)
- [Data Storage](#data-storage)
- [Security Considerations](#security-considerations)

## Getting Started

To use the Password Manager, you need to have Python installed on your system (install it [HERE](https://www.python.org/downloads/)). Once Python is installed, you can install the requirements by running `pip install -r requirements.txt`. Finally, run the program from the terminal by executing the following command:

```batch
python passmgr.py [command] [options]
```

Replace `[command]` with one of the available commands and `[options]` with the appropriate flags and arguments for that command.

## Commands

### Add Account

To add a new account, use the `addAcc` flag followed by the `-accName`, `-accPass`, and optionally `-webMatch` flags.

```batch
python passmgr.py addAcc -accName [Account Name] -accPass [Account Password] -webMatch [URL or Pattern]
```

- `-accName`: Specifies the unique account name.
- `-accPass`: Specifies the password for the account.
- `-webMatch`: (Optional) Allows you to provide a URL or pattern to associate with the account.

### List Accounts

To list all stored accounts, use the `listAcc` flag.

```batch
python passmgr.py listAcc
```

### Remove Account

To remove an account, use the `removeAcc` flag followed by the `-accName` flag.

```batch
python passmgr.py removeAcc -accName [Account Name]
```

- `-accName`: Specifies the account name to remove.

NOTE: If you have spaces or multiple special characters, wrap your arguments with quotation marks to guarantee proper encryption.

### Generate Password

To generate a secure random password, use the `genPass` flag. You can specify the length of the password and whether to include special characters and numbers.

```batch
python passmgr.py genPass -length [Length] -special -numbers
```

- `-length`: (Optional) Specifies the length of the password. Default is 12.
- `-special`: (Optional) Includes special characters in the password.
- `-numbers`: (Optional) Includes numbers in the password.

### Update Password

To update the password for an existing account, use the `updatePass` flag followed by the `-accName` and `-newPass` flags.

```batch
python passmgr.py -updatePass -accName [Account Name] -newPass [New Password]
```

- `-accName`: Specifies the account name to update.
- `-newPass`: Specifies the new password.

## Master Password

The master password is used to encrypt and decrypt the stored passwords. It is first hashed and salted, which is then used to create an encryption key to your passwords. It **SHOULD NOT** be stored in plain text and should be securely managed by the user. In this basic demo, the master password is hardcoded in the program (line 62), but in a real program, you should securely manage the master password, probably by something like prompting the user to enter it at runtime or using a more secure method of storage like end-to-end encryption (if server-side storage was added in the futurr).

## Data Storage

Account data, including encrypted passwords and associated URLs or patterns, is stored in a JSON file named `accounts.json`. This file is portable and can be easily transferred between different machines or environments. The hashed and salted master password is stored in the `hashes.cryptk` file. I'm aware that this isn't the best place to put it, but its a basic proof of concept I made at 2AM, so please give me some slack :).

## Security Considerations

This program provides basic functionality for managing passwords, but in a real-world program you would need to add more robust security measures like limiting the number of incorrect attempts to enter the master password and using way more secure methods for storing the master password.

## License

I've tried to use only open source modules and tools to make this program, so I think I'm in the clear to submit this as a software protected under [Apache 2.0](https://github.com/Cryptic1526/Password-Manager/blob/main/LICENSE). Use this how you may, add on to it, build off of it, make it your own! Maybe we can get it to a position where I can use this on Linux as a genuine option for password management. Who knows `¯\_(ツ)_/`¯.
