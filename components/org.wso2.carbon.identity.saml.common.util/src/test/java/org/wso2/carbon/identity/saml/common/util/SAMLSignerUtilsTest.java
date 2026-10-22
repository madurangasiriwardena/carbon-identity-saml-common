/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.saml.common.util;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Collections;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

/**
 * Tests for signing SAML objects with software keys and with keys held in an HSM.
 */
public class SAMLSignerUtilsTest {

    private static final String DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static final String DIGEST_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";

    private static OpaqueRSAKeyTestProvider hsmProvider;

    @BeforeClass
    public void initialize() throws Exception {

        SAMLInitializer.doBootstrap();
        hsmProvider = new OpaqueRSAKeyTestProvider(2048);
    }

    @AfterMethod
    public void removeProvider() {

        Security.removeProvider(hsmProvider.getName());
    }

    @DataProvider(name = "algorithms")
    public Object[][] algorithms() {

        return new Object[][]{
                {XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, DIGEST_SHA256},
                {XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, DIGEST_SHA1},
                {XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512, DIGEST_SHA256}
        };
    }

    @Test(dataProvider = "algorithms")
    public void testSignWithSoftwareKey(String signatureAlgorithm, String digestAlgorithm) throws Exception {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        Response response = buildMarshalledResponse(keyPair.getPublic(), keyPair.getPrivate(), signatureAlgorithm,
                digestAlgorithm);

        SAMLSignerUtils.signObjects(Collections.singletonList(response.getSignature()));

        assertTrue(verifies(response, keyPair.getPublic()));
    }

    @Test(dataProvider = "algorithms")
    public void testSignWithOpaqueKeyUsesItsProvider(String signatureAlgorithm, String digestAlgorithm)
            throws Exception {

        // Registered after the JDK providers, like a SunPKCS11 token. SunRsaSign comes first but can't use the key.
        Security.addProvider(hsmProvider);
        Response response = buildMarshalledResponse(hsmProvider.getPublicKey(), hsmProvider.getPrivateKey(),
                signatureAlgorithm, digestAlgorithm);

        SAMLSignerUtils.signObject(response.getSignature());

        assertTrue(verifies(response, hsmProvider.getPublicKey()));
    }

    @Test
    public void testSignatureSurvivesMarshallingAgain() throws Exception {

        Security.addProvider(hsmProvider);
        Response response = buildMarshalledResponse(hsmProvider.getPublicKey(), hsmProvider.getPrivateKey(),
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, DIGEST_SHA256);
        SAMLSignerUtils.signObject(response.getSignature());

        // Callers marshall the response again before they serialize it; the cached, signed DOM must be kept.
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(response).marshall(response);

        assertTrue(verifies(response, hsmProvider.getPublicKey()));
    }

    @Test
    public void testOpaqueKeyFailsWithoutSigningHelper() throws Exception {

        // Shows the problem this class solves: OpenSAML's Signer fixes the provider before it sees the key.
        Security.addProvider(hsmProvider);
        Response response = buildMarshalledResponse(hsmProvider.getPublicKey(), hsmProvider.getPrivateKey(),
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, DIGEST_SHA256);

        expectThrows(SignatureException.class,
                () -> org.opensaml.xmlsec.signature.support.Signer.signObject(response.getSignature()));
    }

    @Test
    public void testSignatureDoesNotVerifyWithOtherKey() throws Exception {

        Security.addProvider(hsmProvider);
        Response response = buildMarshalledResponse(hsmProvider.getPublicKey(), hsmProvider.getPrivateKey(),
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, DIGEST_SHA256);
        SAMLSignerUtils.signObject(response.getSignature());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        assertFalse(verifies(response, generator.generateKeyPair().getPublic()));
    }

    @Test
    public void testOpaqueKeyWithoutProvider() throws Exception {

        // The provider that holds the key is not registered, so no provider accepts the key.
        Response response = buildMarshalledResponse(hsmProvider.getPublicKey(), hsmProvider.getPrivateKey(),
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, DIGEST_SHA256);

        SignatureException e = expectThrows(SignatureException.class,
                () -> SAMLSignerUtils.signObject(response.getSignature()));
        assertTrue(e.getMessage().contains("SHA256withRSA"), e.getMessage());
    }

    @Test
    public void testOpaqueKeyRequiresMarshalledSignature() throws Exception {

        Security.addProvider(hsmProvider);
        Signature signature = buildSignature(hsmProvider.getPublicKey(), hsmProvider.getPrivateKey(),
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);

        expectThrows(SignatureException.class, () -> SAMLSignerUtils.signObject(signature));
    }

    private static Response buildMarshalledResponse(PublicKey publicKey, PrivateKey privateKey,
                                                    String signatureAlgorithm, String digestAlgorithm)
            throws Exception {

        Response response = (Response) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(Response.DEFAULT_ELEMENT_NAME).buildObject(Response.DEFAULT_ELEMENT_NAME);
        response.setID("_" + System.nanoTime());
        Issuer issuer = (Issuer) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME).buildObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue("https://idp.example.com");
        response.setIssuer(issuer);
        Signature signature = buildSignature(publicKey, privateKey, signatureAlgorithm);
        response.setSignature(signature);
        ((SAMLObjectContentReference) signature.getContentReferences().get(0)).setDigestAlgorithm(digestAlgorithm);
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(response).marshall(response);
        return response;
    }

    private static Signature buildSignature(PublicKey publicKey, PrivateKey privateKey, String signatureAlgorithm) {

        Signature signature = (Signature) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(new BasicCredential(publicKey, privateKey));
        signature.setSignatureAlgorithm(signatureAlgorithm);
        signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        return signature;
    }

    /**
     * Verify like a relying party: parse the serialized response again and check its signature in software.
     */
    private static boolean verifies(Response signedResponse, PublicKey publicKey) throws Exception {

        String xml = SerializeSupport.nodeToString(signedResponse.getDOM());
        Response parsed = (Response) UnmarshallUtils.unmarshall(xml);
        Signature signature = parsed.getSignature();
        assertNotNull(signature);
        new SAMLSignatureProfileValidator().validate(signature);
        try {
            SignatureValidator.validate(signature, new BasicCredential(publicKey));
            return true;
        } catch (SignatureException e) {
            return false;
        }
    }
}
