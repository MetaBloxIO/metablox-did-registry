// import { expect } from "chai";
import { ethers, network } from "hardhat";

console.log("=========================");
console.log("Using Network: " + network.name);
console.log("=========================");

describe("Test All", function () {
  before(async () => {});

  describe("Deploy MetaBloxDIDRegistry", function () {
    it("Should set the right name Value", async function () {
      // const name = "demo";

      const instance = await ethers.deployContract("MetaBloxDIDRegistry", [], {});

      await instance.waitForDeployment();

      // await instance.setName(name);
      // // assert that the value is correct
      // expect(await instance.getName()).to.equal(name);
    });
  });
});
