package org.redhat.ctf;

import org.jboss.logging.Logger;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.openapi.annotations.Operation;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/")
public class Hacker {

    private static final Logger LOG = Logger.getLogger(Hacker.class);
    
    @ConfigProperty(name = "api.key")
    String api_key;

    private String exploit = """
	{
  	"action": "migrate-and-destroy",
  	"new_cloud_location": "SRV-99PR",
	"workflow": {
    		"step1_snapshot": { "destination": "hacker-storage-exfil1" },
    		"step2_migrate": { "target": "unr-zone-1828"},
    		"step3_delete": true,
	},
	internals": {
		"is_debug_user": true,
		"mfa_bypass": true,
		"trace_id": "881-Z-ALPHA"
	},
    	"node": "c2-krsrv-04",
    	"owner": "CTF{H4CK3R_Z3R0_ALPHA}",
    	"version": "2.4.1-STABLE"
    }
    """;

    @POST
    @Path("/extract")
    @Consumes(MediaType.WILDCARD)
    @Produces(MediaType.TEXT_PLAIN)
    public String extract(@HeaderParam("x-api-key") String apikey, String data) {

		if (apikey==null || !apikey.equals(api_key)) {
				LOG.info("[USER] denied attempt");
			return "{ error: 'unauthorized; x-api-key http header is incorrect or missing'}";
		}

			LOG.info("[CTF] printing data via curl: "+data);
			return "{ info: 'successfully extracted data' ; data: '" + data + "' }";
	}      
    
    @PUT
    @Path("/killswitch")
    @Consumes(MediaType.WILDCARD) 
    @Produces(MediaType.TEXT_PLAIN)
    public String escape(@HeaderParam("x-api-key") String apikey) {
		if (apikey!=null && apikey.equals(apikey)) {
				LOG.info("[USER] succeeded");
			return exploit;
		}
		return "{ error : 'access denied; x-api-key http header is incorrect or missing' }";
    }

	@GET
    @Consumes(MediaType.WILDCARD) 
    @Produces(MediaType.TEXT_PLAIN)
    public Response check(@HeaderParam("x-api-key") String apikey) {
		if (apikey!=null && apikey.equals(apikey)) {
			//LOG.info("[USER] called / endpoint");
			return Response.ok("{ endpoint: alive }")
					.header("ctf-App-Service-Control", "/killswitch")
					.header("Cache-Control", "no-cache")
					.build();
		}
		return Response.ok("{ error : 'access denied; x-api-key http header is incorrect or missing' }").build();
	}
}
