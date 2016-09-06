# SSL Importer
Here is SSL Importer java application.
Application creates jssecacerts for working with https protocol in java. 

Look at this:
http://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html

1.make distribution:

    gradle clean build

2.extract distribution from the following path:
    
    build/distributions/ssl-importer-xx.zip

3.run

    bin\ssl-importer google.com:443 <passPhrase>

4.follow the instructions.

5.copy generated jssecacerts file to the $JAVA_HOME/lib/security/