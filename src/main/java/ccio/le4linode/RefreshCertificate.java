package ccio.le4linode;

import java.io.FileReader;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.RegistrationBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeConflictException;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.CertificateUtils;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;

import uk.co.solong.linode4j.Linode;

/**
 * 
 * @author es
 *
 */
public class RefreshCertificate {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(RefreshCertificate.class);

	public static void main(String[] args) {
		if(args.length != 5){
			System.out.println("Five parameters requered:");
			System.out.println("pathToAccountPrivateKeyFile pathToDomainPrivateKeyFile domainNamesCommaSeparated nodeBalancerLabel linodeAPI");
			return;
		}

		final String domainNames = args[2];
		final String nodeBalancerLabel = args[3];
		final String linodeApiKey = args[4];
		
		try {
			Integer linodeNbConfigId = findLinodeNodeBalancerConfigId(nodeBalancerLabel, linodeApiKey);
			if(linodeNbConfigId == null){
				LOGGER.error("Cannot find Config for Node Balancer {}", nodeBalancerLabel);
				return;
			}

			// Find the user from LE
			Registration reg = findOrRegisterAccount(args[0]);

	        // Generate a CSR for all of the domains, and sign it with the domain key pair.
			KeyPair domainKey = loadKeyPair(args[1]);
	        CSRBuilder csrb = new CSRBuilder();
	        csrb.addDomains(domainNames.split(","));
	        csrb.sign(domainKey);

	        // Now request a signed certificate.
	        Certificate certificate = reg.requestCertificate(csrb.getEncoded());

	        LOGGER.info("The certificate for domain(s) {} has been generated.", domainNames);
	        LOGGER.info("Certificate URI: {}", certificate.getLocation());

	        // Download the leaf certificate and certificate chain.
	        X509Certificate cert = certificate.download();
	        X509Certificate[] chain = certificate.downloadChain();
	        
	        // Write a combined file containing the certificate and chain.
	        StringWriter chainWriter = new StringWriter();
	        CertificateUtils.writeX509CertificateChain(chainWriter, cert, chain);
	        LOGGER.debug("Certificate Chain\n{}", chainWriter);
	        
	        // Get Domain Key
	        StringWriter domainKeyWriter = new StringWriter();
	        KeyPairUtils.writeKeyPair(domainKey, domainKeyWriter);
	        
	        // update LB
	        JsonNode reply = new Linode(linodeApiKey).updateNodeBalancerConfig(linodeNbConfigId)
	        		.withSslCert(chainWriter.toString())
	        		.withSslKey(domainKeyWriter.toString()).asJson();
	        
	        LOGGER.debug("Linode Node Balancer is updated {}", reply);
	        LOGGER.info("Everything is done. Linode Node Balancer should have a new certificate now.");
		} catch (IOException | AcmeException e) {
			LOGGER.error("Failed updating Linode Node Balancer.", e);
		}
	}
	
	private static Integer findLinodeNodeBalancerConfigId(String nodeBalancerLabel, String linodeApiKey){
		// Find node balancer from Linode
        Linode api = new Linode(linodeApiKey);
		JsonNode reply = api.listNodeBalancers().asJson();
		Integer nbId = null;
		for(Iterator<JsonNode> iter = reply.get("DATA").iterator(); iter.hasNext();){
			JsonNode n = iter.next();
			String nbLabel = n.get("LABEL").asText();
			if(nodeBalancerLabel.equalsIgnoreCase(nbLabel)){
				nbId = n.get("NODEBALANCERID").asInt();
				break;
			}
		}
		if(nbId == null){
			LOGGER.error("NodeBalancer with label {} is not found", nodeBalancerLabel);
			return null;
		}
        
		reply = api.listNodeBalancerConfig(nbId).asJson();
		LOGGER.debug("Linode API returned Node Balancers: {}", reply);
		
		Integer nbConfigId = null;
		for(Iterator<JsonNode> iter = reply.get("DATA").iterator(); iter.hasNext();){
			JsonNode n = iter.next();
			String protocol = n.get("PROTOCOL").asText();
			if("https".equalsIgnoreCase(protocol)){
				nbConfigId = n.get("CONFIGID").asInt();
				break;
			}
		}
		
		if(nbConfigId == null){
			LOGGER.error("NodeBalancer {} doesn't have HTTPS port configured", nodeBalancerLabel);
			return null;
		}
		LOGGER.debug("Node Balancer Config ID is found: {}", nbConfigId);
		return nbConfigId;
	}
	
	private static Registration findOrRegisterAccount(String accountKey) throws AcmeException, IOException {
        Registration reg;
        KeyPair accountKeyPair = loadKeyPair(accountKey);
		Session session = new Session("acme://letsencrypt.org", accountKeyPair);

        try {
            // Try to create a new Registration.
            reg = new RegistrationBuilder().create(session);
            LOGGER.info("Registered a new user, URI: {}", reg.getLocation());

            // This is a new account. Let the user accept the Terms of Service.
            // We won't be able to authorize domains until the ToS is accepted.
            URI agreement = reg.getAgreement();
            LOGGER.info("Terms of Service: {}", agreement);
            reg.modify().setAgreement(agreement).commit();
        } catch (AcmeConflictException ex) {
            // The Key Pair is already registered. getLocation() contains the
            // URL of the existing registration's location. Bind it to the session.
            reg = Registration.bind(session, ex.getLocation());
            LOGGER.info("Account does already exist, URI: {}", reg.getLocation());
        }

        return reg;
    }
	
	private static KeyPair loadKeyPair(String keyPath) throws IOException {
        try (FileReader fr = new FileReader(keyPath)) {
            return KeyPairUtils.readKeyPair(fr);
        }
    }

}
