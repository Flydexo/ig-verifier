import {readFileSync} from "fs";
const inputs = JSON.parse(
  readFileSync("./custom-regexes/inputs.json").toString()
);

console.log(
  Buffer.from(
    inputs.emailBody
      .slice(
        Number(inputs.newMailIndex),
        Number(inputs.newMailIndex) + "matucheo75&#064;gmail.com".length
      )
      .map((a: string) => Number(a)),
    "utf-8"
  ).toString()
);
