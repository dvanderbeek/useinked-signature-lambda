package com.serverless;

import java.util.Collections;
import java.util.Map;
import java.util.Base64;
import java.util.ArrayList;
import java.util.List;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.ICrlClient;
import com.itextpdf.signatures.CrlClientOnline;
import com.itextpdf.signatures.IOcspClient;
import com.itextpdf.signatures.OcspClientBouncyCastle;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.TSAClientBouncyCastle;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import com.amazonaws.AmazonServiceException;

import com.microsoft.azure.keyvault.KeyVaultClient;

public class Handler implements RequestHandler<Map<String, Object>, ApiGatewayResponse> {

	private static final Logger LOG = LogManager.getLogger(Handler.class);

	@Override
	public ApiGatewayResponse handleRequest(Map<String, Object> input, Context context) {
		try {
			JsonNode body = new ObjectMapper().readTree((String) input.get("body"));
			String filename = body.get("filename").asText();

			System.out.println("Starting");
			AmazonS3 client = new AmazonS3Client();
	    S3Object xFile = client.getObject(System.getenv("S3_BUCKET"), filename);
	    InputStream contents = xFile.getObjectContent();
			System.out.println("Got file from s3");

			KeyVaultClient azureClient = getKeyVaultClient();
	    X509Certificate certificate = getKeyVaultCertificate(azureClient);
	    X509Certificate caCert = getCaCert();

	    Certificate[] chain = { certificate, caCert };
			System.out.println("Set up certificate chain");

			KeyVaultSignature externalSignature = new KeyVaultSignature(azureClient, System.getenv("AZURE_KEY_ID"));

			signPdf(contents, chain, externalSignature, filename);

			Response responseBody = new Response("Go Serverless v1.x! Your function executed successfully!", input);
			return ApiGatewayResponse.builder()
					.setStatusCode(200)
					.setObjectBody(responseBody)
					.setHeaders(Collections.singletonMap("X-Powered-By", "AWS Lambda & serverless"))
					.build();
		} catch(Exception e) {
			Response responseBody = new Response("Error signing document: ", input);
			return ApiGatewayResponse.builder()
					.setStatusCode(500)
					.setObjectBody(responseBody)
					.setHeaders(Collections.singletonMap("X-Powered-By", "AWS Lambda & Serverless"))
					.build();
		}
	}

	private static void signPdf(InputStream pdf, Certificate[] chain, IExternalSignature externalSignature, String signedPdfName) {
		System.out.println("Starting signPdf method");
		String tempfile = "/tmp/" + signedPdfName;

		try {

	    FileOutputStream stream = new FileOutputStream(tempfile);
	    PdfReader reader = new PdfReader(pdf);
	    PdfSigner signer = new PdfSigner(reader, stream, false);
	    signer.getSignatureAppearance()
	          .setReason(System.getenv("SIGNING_REASON"))
	          .setLocation(System.getenv("SIGNING_LOCATION"));
	    IExternalDigest digest = new BouncyCastleDigest();
	    ITSAClient tsaClient = new TSAClientBouncyCastle(System.getenv("ENTRUST_TSA_URL"));
	    IOcspClient ocspClient = new OcspClientBouncyCastle(null);
	    List<ICrlClient> crlList = new ArrayList<ICrlClient>();
	    crlList.add(new CrlClientOnline(chain));
	    signer.signDetached(digest, externalSignature, chain, crlList, ocspClient, tsaClient, 0, PdfSigner.CryptoStandard.CMS);

	    // Save back to s3
	    // https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/examples-s3-objects.html#upload-object
	    AmazonS3 s3 = new AmazonS3Client();
	    try {
				ObjectMetadata objectMetadata = new ObjectMetadata();
				objectMetadata.setSSEAlgorithm(ObjectMetadata.AES_256_SERVER_SIDE_ENCRYPTION);
				objectMetadata.setContentType("application/pdf");
				File file = new File(tempfile);
				InputStream signedPdfStream = new FileInputStream(file);
	      s3.putObject(System.getenv("S3_BUCKET"), signedPdfName, signedPdfStream, objectMetadata);
	    } catch (AmazonServiceException e) {
	      System.err.println(e.getErrorMessage());
	      System.exit(1);
	    }

		} catch(Exception e) {
			System.err.println("Error signing document");
			System.exit(1);
		}
	}

	private X509Certificate getCaCert() throws CertificateException {
    ClassLoader classLoader = getClass().getClassLoader();
    InputStream in = classLoader.getResourceAsStream("Chain.pem");
    return getCert(in);
  }

  private X509Certificate getKeyVaultCertificate(KeyVaultClient client) throws CertificateException {
    String certStr = client.getSecret(System.getenv("AZURE_SECRET_ID")).value();
    InputStream in = new ByteArrayInputStream(certStr.getBytes(StandardCharsets.UTF_8));
    return getCert(in);
  }

  private X509Certificate getCert(InputStream in) throws CertificateException {
    X509Certificate certificate = null;
    CertificateFactory factory = CertificateFactory.getInstance("X.509");

    try {
      certificate = (X509Certificate) factory.generateCertificate(in);
    } catch (CertificateException e) {
      throw new CertificateException(e);
    }

    return certificate;
  }

  private KeyVaultClient getKeyVaultClient() {
    ClientSecretKeyVaultCredential creds = getClientSecretKeyVaultCredential();
    return new KeyVaultClient(creds);
  }

  private ClientSecretKeyVaultCredential getClientSecretKeyVaultCredential() {
    return new ClientSecretKeyVaultCredential(System.getenv("AZURE_APPLICATION_ID"), System.getenv("AZURE_SECRET"));
  }
}
