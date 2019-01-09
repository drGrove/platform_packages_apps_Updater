package sh.hashbang.updater;

import java.io.IOException;
import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.util.Set;

import org.bouncycastle.opengpg.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.opengpg.PGPException;

public class SignatureVerification
{
  private static InputStream publicRingKeyIn = new BufferedInputStream(new FileInputStream("./pubring.asc"));

  public static boolean verifiySignatures(
      InputStream updateFile,
      InputStream SignatureFile)
      throws IOException, PGPException
    {
      PGPPublicKeyRingCollection  pgpPubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicRingKeyIn), new JcaKeyFingerprintCalculator());
      PGPSignatureList sigList = generateSignatureList(SignatureFile);
      Set<long> validSignatures = new Set<long>();
      Set<long> seenKeys = new Set<long>();
      Iterator<PGPSignature> sigListIterator = sigList.iterator();
      while (sigListIterator.hasNext()) {
        PGPSignature sig = sigListIterator.next();
        PGPPublicKey key = pgpPubRingCollection.getPublicKey(sig.getKeyID());
        if(seenKeys.has(key.getKeyID())) {
          continue;
        }

        seenKeys.add(key.getKeyID());
        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);
        int ch;
        while ((ch = dIn.read()) >= 0)
        {
          sig.update((byte)ch);
        }

        dIn.close();

        if (sig.verify())
        {
          validSignatures.add(key.getKeyID());
        }
      }

      if (validSignatures.size() > 0) {
        return true;
      }

      return false;
    }

  private static PGPSignatureList(
      InputStream SignatureFile)
      throws PGPException
    {
      in = PGPUtil.getDecoderStream(in);

      JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
      PGPSignatureList p3 = ;

      Object o = pgpFact.nextObject();
      if (o instanceof PGPCompressedData)
      {
        PGPCompressedData c1 = (PGPCompressedData)o;

        pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

        p3 = (PGPSignatureList)pgpFact.nextObject();
      }
      else
      {
        p3 = (PGPSignatureList)o;
      }
      return p3;
    }
}
