import { ethers, network, run } from "hardhat";

async function main() {
  const name = "MetaBloxDIDRegistry";
  const instance = await ethers.deployContract(name, [], {});

  await instance.waitForDeployment();
  console.log(`${name} deployed to ${instance.target}`);

  // If it's the hardhat network, ignore verification
  if (network.name === "hardhat") {
    console.log("hardhat network, ignore verify");
    return;
  }

  const timeWait = 15;
  console.log(`waiting for ${timeWait} seconds... to verify contract`);
  await new Promise((resolve) => setTimeout(resolve, timeWait * 1000));

  run("verify:verify", {
    address: instance.target,
    constructorArguments: [],
  });
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
