package org.attribyte.snook.auth.oauth;

import org.junit.Test;

import static org.junit.Assert.*;

public class PKCETest {

   @Test
   public void testGenerateVerifier() {
      String verifier = PKCE.generateVerifier();
      assertNotNull(verifier);
      assertEquals(PKCE.DEFAULT_VERIFIER_LENGTH, verifier.length());
   }

   @Test
   public void testGenerateVerifierCustomLength() {
      String verifier = PKCE.generateVerifier(128);
      assertEquals(128, verifier.length());
   }

   @Test(expected = IllegalArgumentException.class)
   public void testGenerateVerifierTooShort() {
      PKCE.generateVerifier(10);
   }

   @Test(expected = IllegalArgumentException.class)
   public void testGenerateVerifierTooLong() {
      PKCE.generateVerifier(200);
   }

   @Test
   public void testVerifierContainsOnlyValidChars() {
      String verifier = PKCE.generateVerifier(128);
      for(char c : verifier.toCharArray()) {
         assertTrue("Invalid character in verifier: " + c,
                 (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~');
      }
   }

   @Test
   public void testComputeChallenge() {
      String challenge = PKCE.computeChallenge("test_verifier_value");
      assertNotNull(challenge);
      assertFalse(challenge.isEmpty());
      assertFalse("Challenge should not contain padding", challenge.contains("="));
   }

   @Test
   public void testComputeChallengeDeterministic() {
      String challenge1 = PKCE.computeChallenge("same_verifier");
      String challenge2 = PKCE.computeChallenge("same_verifier");
      assertEquals(challenge1, challenge2);
   }

   @Test
   public void testComputeChallengeDifferentInputs() {
      String challenge1 = PKCE.computeChallenge("verifier_one");
      String challenge2 = PKCE.computeChallenge("verifier_two");
      assertNotEquals(challenge1, challenge2);
   }

   @Test
   public void testValidate() {
      String verifier = PKCE.generateVerifier();
      String challenge = PKCE.computeChallenge(verifier);
      assertTrue(PKCE.validate(verifier, challenge));
   }

   @Test
   public void testValidateFailsWithWrongVerifier() {
      String verifier = PKCE.generateVerifier();
      String challenge = PKCE.computeChallenge(verifier);
      String wrongVerifier = PKCE.generateVerifier();
      assertFalse(PKCE.validate(wrongVerifier, challenge));
   }

   @Test
   public void testValidateFailsWithWrongChallenge() {
      String verifier = PKCE.generateVerifier();
      assertFalse(PKCE.validate(verifier, "wrong_challenge_value"));
   }

   @Test
   public void testRfc7636TestVector() {
      // RFC 7636 Appendix B test vector
      // code_verifier = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
      // expected code_challenge = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
      String expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
      assertEquals(expectedChallenge, PKCE.computeChallenge(verifier));
      assertTrue(PKCE.validate(verifier, expectedChallenge));
   }
}
