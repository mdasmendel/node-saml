import { pki, util, pem } from "node-forge";
import { KeyInfo } from "xml-crypto";

export class KeyInfoProvider implements KeyInfo {
  _certificatePEM: string;

  constructor(certificatePEM: string | Buffer) {
    if (Buffer.isBuffer(certificatePEM)) {
      certificatePEM = certificatePEM.toString("ascii");
    }

    if (certificatePEM == null || typeof certificatePEM !== "string") {
      throw new Error("certificatePEM must be a valid certificate in PEM format");
    }
    this._certificatePEM = certificatePEM;
  }

  getKeyInfo(key: string | undefined, prefix = "") {
    prefix = prefix ? prefix + ":" : prefix;

    const certBodyInB64 = util.encode64(pem.decode(this._certificatePEM)[0].body);
    const certObj = pki.certificateFromPem(this._certificatePEM);

    let keyInfoXml = "<" + prefix + "X509Data>";

    keyInfoXml += "<" + prefix + "X509SubjectName>";
    keyInfoXml += getSubjectName(certObj);
    keyInfoXml += "</" + prefix + "X509SubjectName>";

    keyInfoXml += "<" + prefix + "X509Certificate>";
    keyInfoXml += certBodyInB64;
    keyInfoXml += "</" + prefix + "X509Certificate>";

    keyInfoXml += "</" + prefix + "X509Data>";

    return keyInfoXml;
  }

  getKey(keyInfo?: Node[] | null): Buffer {
    if (keyInfo) {
      const jsonString = JSON.stringify(keyInfo);
      return Buffer.from(jsonString);
    }
    return Buffer.from(this._certificatePEM);
  }
}

function getSubjectName(certObj: any) {
  let subjectFields;
  const fields = ["CN", "OU", "O", "L", "ST", "C"];

  if (certObj.subject) {
    subjectFields = fields.reduce(function (subjects: string[], fieldName) {
      const certAttr = certObj.subject.getField(fieldName);

      if (certAttr) {
        subjects.push(fieldName + "=" + certAttr.value);
      }

      return subjects;
    }, []);
  }

  return Array.isArray(subjectFields) ? subjectFields.join(",") : "";
}
