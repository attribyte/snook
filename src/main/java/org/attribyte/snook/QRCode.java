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

import com.google.common.base.MoreObjects;
import com.google.common.base.Preconditions;
import com.google.common.collect.Maps;
import io.nayuki.qrcodegen.QrCode;
import io.nayuki.qrcodegen.QrSegment;
import org.checkerframework.checker.nullness.qual.NonNull;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;

/**
 * Generate QR codes.
 * See: https://www.nayuki.io/page/qr-code-generator-library
 */
public class QRCode {

   /**
    * Generate a QR code from the command line.
    * {@code -outputFile, -scale, -border, -lightColor, -darkColor, -mask, -minVersion, -maxVersion, -boostEcl}
    * @param args The arguments.
    */
   public static void main(String [] args) throws IOException {

      Map<String, String> parameterMap = Maps.newHashMap();
      args = Util.commandLineParameters(args, parameterMap);
      if(args.length < 1) {
         System.err.println("Usage: [property file] <text to encode>)");
         System.exit(1);
      }

      final String text = args[0];

      if(parameterMap.containsKey("properties")) {
         Properties properties = new Properties();
         try(FileInputStream fis = new FileInputStream(parameterMap.get("properties"))) {
            properties.load(fis);
         }
         properties.forEach((k,v) -> {
            parameterMap.put(k.toString(),v.toString());
         });
      }

      Options.Builder options = Options.builder();
      if(parameterMap.containsKey("scale")) {
         options.setScale(Integer.parseInt(parameterMap.get("scale")));
      }

      if(parameterMap.containsKey("border")) {
         options.setScale(Integer.parseInt(parameterMap.get("border")));
      }

      if(parameterMap.containsKey("reverseColor")) {
         options.setDarkColor(DEFAULT_LIGHT);
         options.setLightColor(DEFAULT_DARK);
      }

      boolean transparentBackground;
      if(parameterMap.containsKey("transparentBackground")) {
         transparentBackground = parameterMap.get("transparentBackground").equalsIgnoreCase("true");
         options.setTransparentBackground(transparentBackground);
      } else {
         transparentBackground = DEFAULT_TRANSPARENT_BACKGROUND;
      }

      if(parameterMap.containsKey("lightColor")) {
         options.setLightColor(parseColor(parameterMap.get("lightColor"), transparentBackground));
         if(options.lightColor == -1) {
            transparentBackground = true;
         }
      }

      if(parameterMap.containsKey("darkColor")) {
         options.setDarkColor(parseColor(parameterMap.get("darkColor"), transparentBackground));
      }

      if(parameterMap.containsKey("mask")) {
         options.setMask(Integer.parseInt(parameterMap.get("mask")));
      }

      if(parameterMap.containsKey("minVersion")) {
         options.setMask(Integer.parseInt(parameterMap.get("minVersion")));
      }

      if(parameterMap.containsKey("maxVersion")) {
         options.setMask(Integer.parseInt(parameterMap.get("maxVersion")));
      }

      if(parameterMap.containsKey("boostEcl")) {
         options.setBoostEcl(parameterMap.get("boostEcl").equalsIgnoreCase("true"));
      }

      if(parameterMap.containsKey("ecc")) {
         switch(parameterMap.get("ecc").toLowerCase().trim()) {
            case "low":
               options.setEcc(ECC.LOW);
               break;
            case "med":
               options.setEcc(ECC.MEDIUM);
               break;
            case "high":
               options.setEcc(ECC.HIGH);
         }
      }

      if(parameterMap.containsKey("outputFile")) {
         try(final FileOutputStream fos = new FileOutputStream(parameterMap.get("outputFile"))) {
            generateQRCode(text, options.build(), fos);
         }
      } else {
         generateQRCode(text, options.build(), System.out);
      }
   }

   private static int parseColor(final String text, final boolean transparentBackground) {
      if(text.startsWith("0x")) {
         String toParse = text.substring(2);
         if(transparentBackground && text.length() == 6) {
            toParse = "FF" + toParse;
         }
         return Integer.parseInt(toParse, 16);
      } else {
         return Integer.parseInt(text);
      }
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
    * The default dark color ({@value}).
    */
   public static final int DEFAULT_DARK = 0x000000;

   /**
    * The default dark color ({@value}).
    */
   public static final int DEFAULT_DARK_TRANSPARENT = 0xFF000000;

   /**
    * The default light color ({@value}).
    */
   public static final int DEFAULT_LIGHT = 0xFFFFFF;

   /**
    * The default minimum version ({@value}).
    */
   public static final int DEFAULT_MIN_VERSION = 1;

   /**
    * The default maximum version ({@value}).
    */
   public static final int DEFAULT_MAX_VERSION = 40;

   /**
    * The default mask ({@value}).
    */
   public static final int DEFAULT_MASK = -1;

   /**
    * The default ECL boost ({@value}).
    */
   public static final boolean DEFAULT_BOOST_ECL = true;

   /**
    * The default transparent background ({@value}).
    */
   public static final boolean DEFAULT_TRANSPARENT_BACKGROUND = true;

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
    * QR code generation options.
    */
   public static class Options {

      /**
       * The default options.
       */
      public static final Options DEFAULT =
              new Options(ECC.MEDIUM, DEFAULT_SCALE, DEFAULT_BORDER, DEFAULT_DARK, DEFAULT_LIGHT,
                      DEFAULT_MIN_VERSION, DEFAULT_MAX_VERSION, DEFAULT_MASK, DEFAULT_BOOST_ECL,
                      DEFAULT_TRANSPARENT_BACKGROUND);

      /**
       * Black on transparent background with all other default settings.
       */
      public static final Options STANDARD_TRANSPARENT =
              new Options(ECC.MEDIUM, DEFAULT_SCALE, DEFAULT_BORDER, DEFAULT_DARK_TRANSPARENT, DEFAULT_LIGHT,
                      DEFAULT_MIN_VERSION, DEFAULT_MAX_VERSION, DEFAULT_MASK, DEFAULT_BOOST_ECL,
                      true);

      public static class Builder {

         public ECC getEcc() {
            return ecc;
         }

         public Builder setEcc(final ECC ecc) {
            this.ecc = ecc;
            return this;
         }

         public int getScale() {
            return scale;
         }

         public Builder setScale(final int scale) {
            this.scale = scale;
            return this;
         }

         public int getBorder() {
            return border;
         }

         public Builder setBorder(final int border) {
            this.border = border;
            return this;
         }

         public int getDarkColor() {
            return darkColor;
         }

         public Builder setDarkColor(final int darkColor) {
            this.darkColor = darkColor;
            return this;
         }

         public int getLightColor() {
            return lightColor;
         }

         public void setLightColor(final int lightColor) {
            this.lightColor = lightColor;
         }

         public int getMinVersion() {
            return minVersion;
         }

         public Builder setMinVersion(final int minVersion) {
            this.minVersion = minVersion;
            return this;
         }

         public int getMaxVersion() {
            return maxVersion;
         }

         public Builder setMaxVersion(final int maxVersion) {
            this.maxVersion = maxVersion;
            return this;
         }

         public int getMask() {
            return mask;
         }

         public Builder setMask(final int mask) {
            this.mask = mask;
            return this;
         }

         public boolean isBoostEcl() {
            return boostEcl;
         }

         public Builder setBoostEcl(final boolean boostEcl) {
            this.boostEcl = boostEcl;
            return this;
         }

         public boolean isTransparentBackground() {
            return transparentBackground;
         }

         public Builder setTransparentBackground(final boolean transparentBackground) {
            this.transparentBackground = transparentBackground;
            return this;
         }

         /**
          * Builds immutable options.
          * @return The options.
          */
         public Options build() {
            return new Options(ecc, scale, border, darkColor, lightColor, minVersion, maxVersion, mask,
                    boostEcl, transparentBackground);
         }

         private ECC ecc = ECC.MEDIUM;
         private int scale = DEFAULT_SCALE;
         private int border = DEFAULT_BORDER;
         private int darkColor = DEFAULT_DARK;
         private int lightColor = DEFAULT_LIGHT;
         private int minVersion = DEFAULT_MIN_VERSION;
         private int maxVersion = DEFAULT_MAX_VERSION;
         private int mask = DEFAULT_MASK;
         private boolean boostEcl = DEFAULT_BOOST_ECL;
         private boolean transparentBackground = DEFAULT_TRANSPARENT_BACKGROUND;
      }


      /**
       * Creates a new options builder with pre-set defaults.
       * @return The builder.
       */
      public static Builder builder() {
         return new Builder();
      }

      public Options(final ECC ecc, final int scale, final int border,
                     final int darkColor, final int lightColor,
                     final int minVersion, final int maxVersion,
                     final int mask, final boolean boostEcl,
                     final boolean transparentBackground) {
         this.ecc = ecc;
         this.scale = scale;
         this.border = border;
         this.darkColor = darkColor;
         this.lightColor = lightColor;
         this.minVersion = minVersion;
         this.maxVersion = maxVersion;
         this.mask = mask;
         this.boostEcl = boostEcl;
         this._transparentBackground = transparentBackground;
      }

      /**
       * Change the scale and border.
       * @param scale The scale.
       * @param border The border.
       * @return The options with scale and border changed.
       */
      public Options withScaleAndBorder(final int scale, final int border) {
         return new Options(ecc, scale, border, darkColor, lightColor, minVersion, maxVersion, mask, boostEcl,
                 _transparentBackground);
      }

      @Override
      public String toString() {
         return MoreObjects.toStringHelper(this)
                 .add("ecc", ecc)
                 .add("scale", scale)
                 .add("border", border)
                 .add("darkColor", darkColor)
                 .add("lightColor", lightColor)
                 .add("minVersion", minVersion)
                 .add("maxVersion", maxVersion)
                 .add("mask", mask)
                 .add("boostEcl", boostEcl)
                 .add("transparentBackground", transparentBackground())
                 .toString();
      }

      /**
       * The ECC level.
       */
      public final ECC ecc;

      /**
       * The scale.
       */
      public final int scale;

      /**
       * The border.
       */
      public final int border;

      /**
       * The dark color.
       */
      public final int darkColor;

      /**
       * The light color.
       */
      public final int lightColor;

      public final int minVersion;

      public final int maxVersion;

      public final int mask;

      public final boolean boostEcl;

      public boolean transparentBackground() {
         return _transparentBackground || lightColor == -1;
      }

      private final boolean _transparentBackground;
   }

   /**
    * Generates a QR code (as a PNG) with default values.
    * @param text The embedded text.
    * @param os The output stream.
    * @throws IOException on write error.
    */
   public static void generateQRCode(final String text,
                                     final OutputStream os) throws IOException {
      generateQRCode(text, Options.DEFAULT, os);
   }

   /**
    * Generates a QR code (as a PNG) with custom options.
    * @param text The embedded text.
    * @param options The options.
    * @param os The output stream (not closed).
    * @throws IOException on write error.
    */
   public static void generateQRCode(final String text, final Options options,
                                     final OutputStream os) throws IOException {
      BufferedImage img = toImage(encodeText(text, options), options);
      OutputStream bos = new BufferedOutputStream(os);
      ImageIO.write(img, "png", bos);
      img.flush();
   }

   /**
    * Returns a raster image depicting the specified QR Code, with the specified module scale and border modules.
    * <p>For example, toImage(qr, scale=10, border=4) means to pad the QR Code with 4 light
    * border modules on all four sides, and use 10&#xD7;10 pixels to represent each module.
    * The resulting image only contains the hex colors 000000 and FFFFFF.
    * @param qr the QR Code to render (not {@code null})
    * @param scale the side length (measured in pixels, must be positive) of each module
    * @param border the number of border modules to add, which must be non-negative
    * @return a new image representing the QR Code, with padding and scaling
    * @throws IllegalArgumentException if the scale or border is out of range, or if
    * {scale, border, size} cause the image dimensions to exceed Integer.MAX_VALUE
    */
   public static final BufferedImage toImage(@NonNull QrCode qr, final int scale,
                                             final int border) {
      return toImage(qr, Options.DEFAULT.withScaleAndBorder(scale, border));
   }

   /**
    * Copied from: https://github.com/nayuki/QR-Code-generator/blob/master/java/QrCodeGeneratorDemo.java
    * Returns a raster image depicting the specified QR Code, with the specified module scale and border modules.
    * <p>For example, toImage(qr, scale=10, border=4) means to pad the QR Code with 4 light
    * border modules on all four sides, and use 10&#xD7;10 pixels to represent each module.
    * @param qr the QR Code to render (not {@code null})
    * @param options The QR code options.
    * @return a new image representing the QR Code, with padding and scaling
    * @throws IllegalArgumentException if the scale or border is out of range, or if
    * {scale, border, size} cause the image dimensions to exceed Integer.MAX_VALUE
    */
   public static final BufferedImage toImage(@NonNull QrCode qr, final Options options) {
      Preconditions.checkArgument(options.scale > 0);
      Preconditions.checkArgument(options.border >= 0);
      BufferedImage result = new BufferedImage((qr.size + options.border * 2) * options.scale, (qr.size + options.border * 2) * options.scale,
              options.transparentBackground() ? BufferedImage.TYPE_INT_ARGB : BufferedImage.TYPE_INT_RGB);
      for (int y = 0; y < result.getHeight(); y++) {
         for (int x = 0; x < result.getWidth(); x++) {
            boolean color = qr.getModule(x / options.scale - options.border, y / options.scale - options.border);
            if(options.transparentBackground() && color) {
               if(options.darkColor == DEFAULT_DARK) {
                  result.setRGB(x, y, DEFAULT_DARK_TRANSPARENT);
               } else {
                  result.setRGB(x, y, options.darkColor);
               }
            } else {
               result.setRGB(x, y, color ? options.darkColor : options.lightColor);
            }
         }
      }
      return result;
   }

   /**
    * Encode text with all options.
    * @param text The text.
    * @param options The options.
    * @return The QR code.
    */
   private static QrCode encodeText(CharSequence text, Options options) {
      Objects.requireNonNull(text);
      final QrCode.Ecc ecl;
      switch(options.ecc) {
         case LOW:
            ecl = QrCode.Ecc.LOW;
            break;
         case HIGH:
            ecl = QrCode.Ecc.HIGH;
            break;
         default:
            ecl =QrCode.Ecc.MEDIUM;
            break;
      }
      return QrCode.encodeSegments(QrSegment.makeSegments(text), ecl, options.minVersion, options.maxVersion, options.mask, options.boostEcl);
   }
}
