# Let's Encrypt for Linode
The library retreaves certificates from [Let's Encrypt](https://letsencrypt.org/) for verified domains 
and updates [Linode](https://www.linode.com/) NodeBalancer's SSL certificate.

Just schedule to run it weekly or any other period of time you desire.

## Setting up

Make sure you have Java version 8 or higher
```
java -version
```
Download `le4linode.jar` from [the latest release](https://github.com/CloudCluster/letsencrypt4linode/releases).

## Running the tool

The tool requeres 5 parameter, all of them are requered and must be in the defined order:
```
java -jar le4linode.jar pathToAccountPrivateKeyFile pathToDomainPrivateKeyFile domainNamesCommaSeparated nodeBalancerLabel linodeAPIToken
```

The domains must already be verified with the account the private key you are providing. I'm using 
[Java ACME Clinet](https://github.com/porunov/acme_client), but you can use any client you like. This is one time job. 
Once you verified the domains you just need to keep your Account Key and Domain Key, this will be enough for certificates renewal. 
You can follow [this instruction](https://github.com/porunov/acme_client/wiki/Scenario-1:-Get-a-certificate-for-different-domains) 
to create the keys and verify your domains.
