# Utils

[![nuget](https://img.shields.io/nuget/v/Thrzn41.Util.svg)](https://www.nuget.org/packages/Thrzn41.Util) [![MIT license](https://img.shields.io/github/license/thrzn41/Utils.svg)](https://github.com/thrzn41/Utils/blob/master/LICENSE)

Utils that are used in thrzn41 projects.

---
## Available Platforms

* .NET Standard 1.3 or later
* .NET Core 1.0 or later
* .NET Framework 4.5.2 or later

---
## Available Features

* `SlimLock` to lock threads.
* `SlimAsyncLock` to lock tasks.
* `CryptoRandom` to generate cryptographically secure random.
* `LocalProtectedString` to encrypt string by local user or machine only token.
* `PBEProtectedString` to encrypt string by password based encryption.
* `HashString` to generate hash string.
* `HttpUtils` for http.
* `UTF8Utils` for utf-8 encoding.

---
## Examples

### SlimLock

``` csharp
SlimLock slimLock = new SlimLock();


// In Thread-A.
using(slimLock.EnterLockedReadBlock())
{
    var value = ReadFromSharedResouce();
}



// In Thread-B.
using(slimLock.EnterLockedWriteBlock())
{
    WriteToSharedResouce(someValue);
}
```


### CryptoRandom

``` csharp
var rand = new CryptoRandom();

int value = rand.NextInt(100);

var sequence = rand.GetASCIIChars(16);
```
