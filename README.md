OpenID Connect client in C#
===========================

To configure .NET platform for testing (on Windows):
- register certificate.pfx in management console between personal certificates
- execute the following command to register ssl certificate for .NET https:
```
%systemroot%\system32\netsh http add sslcert ipport=127.0.0.1:8090 certhash=4bfc5563229b3b81eaf795b5afb3786a80dade61 appid={E71D1FC0-DCB8-418E-82D1-17C300EA2CC3}
```
