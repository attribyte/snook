/*
 * Copyright 2020 Attribyte, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied.
 *
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

package org.attribyte.snook;

import io.nayuki.qrcodegen.QrCode;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Generate QR codes.
 * See: https://www.nayuki.io/page/qr-code-generator-library
 */
public class QRCode {

   /**
    * The error correction level.
    */
   public enum ECC {

      /**
       * Low error correction.
       */
      LOW,

      /**
       * Medium error correction.
       */
      MEDIUM,

      /**
       * High error correction.
       */
      HIGH
   }

   /**
    * The default scale ({@value}).
    */
   public static final int DEFAULT_SCALE = 4;

   /**
    * The default border ({@value}).
    */
   public static final int DEFAULT_BORDER = 10;

   /**
    * Generates a QR code (as a PNG) with default values.
    * @param text The embedded text.
    * @param os The output stream.
    * @throws IOException on write error.
    */
   public static void generateQRCode(final String text, OutputStream os) throws IOException {
      generateQRCode(text, ECC.MEDIUM, DEFAULT_SCALE, DEFAULT_BORDER, os);
   }

   /**
    * Generates a QR code (as a PNG).
    * @param text The embedded text.
    * @param ecc The error correction level.
    * @param scale The side length of each module in pixels.
    * @param border The number of border modules.
    * @param os The output stream.
    * @throws IOException on write error.
    */
   public static void generateQRCode(final String text, ECC ecc,
                                     int scale, int border,
                                     OutputStream os) throws IOException {
      final QrCode qr;
      switch(ecc) {
         case LOW:
            qr = QrCode.encodeText(text, QrCode.Ecc.LOW);
            break;
         case HIGH:
            qr = QrCode.encodeText(text, QrCode.Ecc.HIGH);
            break;
         default:
            qr = QrCode.encodeText(text, QrCode.Ecc.MEDIUM);
            break;
      }

      BufferedImage img = qr.toImage(scale, border);
      OutputStream fos = new BufferedOutputStream(os);
      ImageIO.write(img, "png", fos);
      img.flush();
   }
}
