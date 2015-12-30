OpenID Connect client in C#
===========================

This project contains a full implementation of an OpenID Connect Relying Party written in C#.

A Sample application has also been developed to test integration of this authentication mechanism into MVC .NET apps.
The main configuration steps done within this sample app are the following:

1. add the in ``configSessions`` this line:
   ```
<section name="openid.authServices" type="OpenIDClient.HttpModule.Configuration.OpenIDConfigurationSection, OpenIDClient.HttpModule" />
   ```
1. add a specific configuration section to describe the configuration for the RP.
   The parameters that can be specified are the following:
   - flag indicating whether to check SSL certificates or not
   - certificate to be used for signing messages for the OP (optional)
   - certificate to be used for encryption messages for the OP (optional)
   - list of OPs, with the following attributes:
     . an identifier (string name of the OP)
	 . flag indicating whether the OP supports dynamic client registration
	 . client id and secret, in case the OP does not support dynamic client registration
	 . OP issuer
	 . flag indicating if signature of messages must be enabled for this OP
	 . flag indicating if encryption of messages must be enabled for this OP
  An example of configuration is the one present in the ``Web.config``, here below:
  ```
<openid.authServices checkSslCertificate="false">
    <signCertificate fileName="~/App_Data/OpenID.AuthServices.RP.Sign.pfx" />
    <encCertificate fileName="~/App_Data/OpenID.AuthServices.RP.Enc.pfx" />
    <openidProviders>
      <add entityId="Google"
           selfRegistration="false"
           clientId="401966304375-rvft4r8u2gu33f8347irle15f49b03jd.apps.googleusercontent.com"
           clientSecret="rfEgTtEg1zi-WxR6bvTyvApd"
           opIssuer="https://accounts.google.com" />
      <add entityId="OP1 test InAccademia"
           selfRegistration="true"
           opIssuer="https://op1.test.inacademia.org"
           sign="true"
           encrypt="true" />
      <add entityId="Certification test suite"
           selfRegistration="true"
           opIssuer="https://localhost:8080/id/_/_/_/normal"
           sign="true"
           encrypt="true" />
    </openidProviders>
  </openid.authServices>
```

## RP certification
The library is well ahead in the process of certificating as an OpenID Connect RP with the official certification testing suite.
In the ``OIDC.Tests`` project all the tests implemented are present (with names and ID referring to certification test cases).

To configure .NET platform for testing (on Windows):
- register certificate.pfx in management console between personal certificates
- execute the following command to register ssl certificate for .NET https:
```
%systemroot%\system32\netsh http add urlacl url="https://127.0.0.1:8090/" user=Everyone

%systemroot%\system32\netsh http add sslcert ipport=127.0.0.1:8090 certhash=4bfc5563229b3b81eaf795b5afb3786a80dade61 appid={E71D1FC0-DCB8-418E-82D1-17C300EA2CC3}
```
