package org.attribyte.snook.auth;

import com.google.common.base.Charsets;
import com.google.common.collect.Lists;
import com.google.common.hash.HashCode;
import org.attribyte.snook.auth.Authenticator;
import org.attribyte.snook.auth.BCryptAuthenticator;
import org.attribyte.snook.auth.CredentialsFile;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.List;

import static org.junit.Assert.*;

public class CredentialsFileTest {

   @Test
   public void generateToken() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester:$token$");
      List<CredentialsFile.Record> records = CredentialsFile.parse(lines, true);
      assertEquals(1, records.size());
      CredentialsFile.Record record = records.get(0);
      assertNotNull(record.value);
      assertEquals(CredentialsFile.HashType.SHA256, record.hashType);
      assertEquals("tester:$token$" + record.value, record.toLine());
      assertNotNull(record.hashCode);
   }

   @Test
   public void generatePassword() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester:$password$");
      List<CredentialsFile.Record> records = CredentialsFile.parse(lines, true);
      assertEquals(1, records.size());
      CredentialsFile.Record record = records.get(0);
      assertEquals(CredentialsFile.HashType.BCRYPT, record.hashType);
      assertNotNull(record.hashCode);
   }

   @Test
   public void convertToSecure() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester:$password$");
      lines.add("tester:$token$");
      List<CredentialsFile.Record> records = CredentialsFile.parse(lines, true);
      assertEquals(2, records.size());
      List<CredentialsFile.Record> secureRecords = CredentialsFile.toSecure(records);
      assertEquals(2, secureRecords.size());
      assertTrue(secureRecords.get(0).toLine().startsWith("tester:$2a$11$"));
      assertTrue(secureRecords.get(1).toLine().startsWith("tester:$sha256$"));
   }

   @Test
   public void maps() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester0:$password$123456789012");
      lines.add("tester1:$token$123456789012123456789012123456789012");
      List<CredentialsFile.Record> records = CredentialsFile.parse(lines, true);
      assertEquals(2, records.size());
      CredentialsFile users = new CredentialsFile(records);
      assertEquals(1, users.bcryptHashes.size());
      assertEquals(1, users.sha256Hashes.size());
      assertEquals(2, users.userForHash.size());
      String user0 = users.userForHash.getOrDefault(records.get(0).hashCode, "");
      assertEquals("tester0", user0);
      String user1 = users.userForHash.getOrDefault(records.get(1).hashCode, "");
      assertEquals("tester1", user1);
      HashCode user0Hash = users.bcryptHashes.get("tester0");
      assertNotNull(user0Hash);
      assertTrue(BCryptAuthenticator.checkPassword("123456789012", user0Hash));
      assertFalse(BCryptAuthenticator.checkPassword("x123456789012", user0Hash));
      HashCode user1Hash = users.sha256Hashes.get("tester1");
      assertNotNull(user1Hash);
      assertEquals(Authenticator.hashCredentials("123456789012123456789012123456789012"), user1Hash);
   }

   @Test(expected = IOException.class)
   public void dupeHash() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester0:$token$123456789012123456789012123456789012");
      lines.add("tester1:$token$123456789012123456789012123456789012");
      List<CredentialsFile.Record> records = CredentialsFile.parse(lines, true);
      assertEquals(2, records.size());
      CredentialsFile users = new CredentialsFile(records);
   }


   @Test
   public void preserveLines() throws IOException  {
      List<String> lines = Lists.newArrayList();
      lines.add("tester:$password$");
      lines.add("tester:$token$");
      lines.add("");
      lines.add("#comment");

      List<CredentialsFile.Record> records = CredentialsFile.parse(lines, true);
      assertEquals(4, records.size());
      List<CredentialsFile.Record> secureRecords = CredentialsFile.toSecure(records);
      assertEquals(2, secureRecords.size());
      assertTrue(secureRecords.get(0).toLine().startsWith("tester:$2a$11$"));
      assertTrue(secureRecords.get(1).toLine().startsWith("tester:$sha256$"));
   }

   @Test
   public void generateFiles() throws IOException  {

      String inputLines = ("btester:$basic$\ntester:$password$\ntester:$token$\n\n#comment");
      File secureFile = Files.createTempFile("secure_", ".txt").toFile();
      File insecureFile = Files.createTempFile("insecure_", ".txt").toFile();

      try(InputStream is = new ByteArrayInputStream(inputLines.getBytes(Charsets.UTF_8))) {
         CredentialsFile.generateFiles(is, secureFile, insecureFile, true);
         CredentialsFile users = new CredentialsFile(secureFile);
         assertEquals(3, users.userForHash.size());
         assertEquals(2, users.sha256Hashes.size());
         assertEquals(1, users.bcryptHashes.size());
      } finally {
         secureFile.delete();
         insecureFile.delete();
      }
   }
}
