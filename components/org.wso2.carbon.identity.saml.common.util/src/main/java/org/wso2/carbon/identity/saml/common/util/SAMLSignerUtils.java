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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Element;

import java.security.InvalidParameterException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.List;

/**
 * Signs marshalled OpenSAML signatures. Use it instead of {@link Signer#signObject(Signature)} and
 * {@link Signer#signObjects(List)}.
 * <p>
 * Software keys are signed with {@link Signer}, as before. A key held in an HSM (for example a sensitive SunPKCS11
 * key) has no key material in the JVM, so only its own security provider can sign with it. Santuario fixes the
 * provider of an XML signature when the signature is created, before the key is known, and picks the first provider
 * that offers the algorithm. For such keys this class builds the XML signature again from the marshalled DOM, with
 * the provider that accepts the key, and signs it. Digests are still computed in software.
 */
public class SAMLSignerUtils {

    private static final Log log = LogFactory.getLog(SAMLSignerUtils.class);
    private static final String SIGNATURE_SERVICE = "Signature";

    private SAMLSignerUtils() {

    }

    /**
     * Sign the given signatures. Each signature must be marshalled and have a signing credential.
     *
     * @param signatures Signatures to sign.
     * @throws SignatureException If a signature can't be computed.
     */
    public static void signObjects(List<Signature> signatures) throws SignatureException {

        for (Signature signature : signatures) {
            signObject(signature);
        }
    }

    /**
     * Sign the given signature. The signature must be marshalled and have a signing credential.
     *
     * @param signature Signature to sign.
     * @throws SignatureException If the signature can't be computed.
     */
    public static void signObject(Signature signature) throws SignatureException {

        Key key = CredentialSupport.extractSigningKey(signature.getSigningCredential());
        if (!(key instanceof PrivateKey) || !isKeyMaterialInaccessible((PrivateKey) key)) {
            Signer.signObject(signature);
            return;
        }
        signWithKeyProvider(signature, (PrivateKey) key);
    }

    /**
     * A key held in an HSM is not one of the software key types, or has no encoding.
     */
    private static boolean isKeyMaterialInaccessible(PrivateKey key) {

        boolean softwareKeyType = key instanceof RSAPrivateKey || key instanceof ECPrivateKey ||
                key instanceof DSAPrivateKey;
        return !softwareKeyType || key.getEncoded() == null;
    }

    private static void signWithKeyProvider(Signature signature, PrivateKey key) throws SignatureException {

        Element signatureElement = signature.getDOM();
        if (signatureElement == null) {
            throw new SignatureException("The signature must be marshalled before it is signed.");
        }
        if (!Init.isInitialized()) {
            Init.init();
        }
        String algorithmURI = signature.getSignatureAlgorithm();
        String jcaAlgorithm = JCEMapper.translateURItoJCEID(algorithmURI);
        if (jcaAlgorithm == null) {
            throw new SignatureException("Unsupported signature algorithm: " + algorithmURI);
        }
        Provider provider = getProviderForKey(jcaAlgorithm, key);
        if (provider == null) {
            throw new SignatureException("No security provider can sign with the " + key.getAlgorithm() +
                    " key using " + jcaAlgorithm + " (" + algorithmURI + ").");
        }
        if (log.isDebugEnabled()) {
            log.debug("Signing with a key held by provider " + provider.getName() + " using " + jcaAlgorithm);
        }
        try {
            XMLSignature xmlSignature = new XMLSignature(signatureElement, "", true, provider);
            // A signature parsed from an element creates its references when they are first read; signing
            // needs them.
            SignedInfo signedInfo = xmlSignature.getSignedInfo();
            for (int i = 0; i < signedInfo.getLength(); i++) {
                signedInfo.item(i);
            }
            // The signature value is written into the marshalled DOM. The XMLSignature cached in the OpenSAML
            // object is not replaced: SignatureImpl.setXMLSignature releases the cached DOM, and marshalling the
            // object again would then drop the signature value.
            xmlSignature.sign(key);
        } catch (XMLSecurityException e) {
            throw new SignatureException("Error while computing the signature with provider " +
                    provider.getName() + ".", e);
        }
    }

    /**
     * Get the first provider whose signature service accepts the key. This is the check that JCA uses to select a
     * provider when the key is known.
     */
    private static Provider getProviderForKey(String jcaAlgorithm, PrivateKey key) {

        for (Provider provider : Security.getProviders()) {
            Provider.Service service = provider.getService(SIGNATURE_SERVICE, jcaAlgorithm);
            if (service == null) {
                continue;
            }
            try {
                if (service.supportsParameter(key)) {
                    return provider;
                }
            } catch (InvalidParameterException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Provider " + provider.getName() + " can't check the key for " + jcaAlgorithm, e);
                }
            }
        }
        return null;
    }
}
