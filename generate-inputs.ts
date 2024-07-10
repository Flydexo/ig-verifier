import {bytesToBigInt, fromHex} from "@zk-email/helpers/dist/binary-format";
import {generateEmailVerifierInputs} from "@zk-email/helpers/dist/input-generators";
import {readFileSync, writeFileSync} from "fs";

export const STRING_PRESELECTOR = "Your new email is";

export type ICircuitInputs = {
  igUsernameIndex: string;
  oldMailIndex: string;
  newMailIndex: string;
  address: string;
  emailHeader: string[];
  emailHeaderLength: string;
  pubkey: string[];
  signature: string[];
  emailBody?: string[] | undefined;
  emailBodyLength?: string | undefined;
  precomputedSHA?: string[] | undefined;
  bodyHashIndex?: string | undefined;
};

export async function generateVerifierCircuitInputs(
  email: string | Buffer,
  ethereumAddress: string
): Promise<ICircuitInputs> {
  const emailVerifierInputs = await generateEmailVerifierInputs(email, {
    shaPrecomputeSelector: STRING_PRESELECTOR,
    maxBodyLength: 2432,
  });

  const bodyRemaining = emailVerifierInputs.emailBody!.map((c) => Number(c)); // Char array to Uint8Array
  const newMailBuffer =
    'Your new email is <span =\r\nstyle=3D"color:#2b5a83;" =\r\nid=3D"body_email">';
  const oldMailBuffer =
    'This =\r\nmessage was sent to <a style=3D"color:#abadae;text-decoration:underline;">=\r\n';
  const usernameBuffer = Buffer.from("and intended for ");

  const usernameIndex =
    Buffer.from(bodyRemaining).indexOf(usernameBuffer) + usernameBuffer.length;
  const oldMailIndex =
    Buffer.from(bodyRemaining).toString().indexOf(oldMailBuffer) +
    oldMailBuffer.length;
  const newMailIndex =
    Buffer.from(bodyRemaining).toString().indexOf(newMailBuffer) +
    newMailBuffer.length;

  const address = bytesToBigInt(fromHex(ethereumAddress)).toString();

  console.log(Buffer.from(bodyRemaining).toString().length);

  return {
    ...emailVerifierInputs,
    igUsernameIndex: usernameIndex.toString(),
    oldMailIndex: oldMailIndex.toString(),
    newMailIndex: newMailIndex.toString(),
    address,
  };
}

(async () => {
  writeFileSync(
    "./custom-regexes/inputs.json",
    JSON.stringify(
      await generateVerifierCircuitInputs(
        readFileSync("./custom-regexes/mail.eml"),
        "0x429952c8d27F515011d623dFC9038152af52C5a8"
      ),
      null,
      2
    )
  );
})();
