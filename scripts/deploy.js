const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("====================================================");
  console.log("Deploying ReportRegistry with account:", deployer.address);
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log("Account balance:", ethers.formatEther(balance), "ETH");

  const ReportRegistryFactory = await ethers.getContractFactory("ReportRegistry");
  const reportRegistry = await ReportRegistryFactory.deploy();
  await reportRegistry.waitForDeployment();

  const contractAddress = await reportRegistry.getAddress();
  console.log("ReportRegistry deployed successfully to:", contractAddress);
  console.log("====================================================");

  // Save deployment artifact for Member 3 (Backend API) and frontend integration
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const deploymentData = {
    address: contractAddress,
    network: (await ethers.provider.getNetwork()).name || "localhost",
    chainId: Number((await ethers.provider.getNetwork()).chainId),
    deployedAt: new Date().toISOString(),
    deployer: deployer.address,
    abi: JSON.parse(reportRegistry.interface.formatJson()),
  };

  fs.writeFileSync(
    path.join(deploymentsDir, "ReportRegistry.json"),
    JSON.stringify(deploymentData, null, 2)
  );

  console.log(`Deployment metadata written to: ${path.join(deploymentsDir, "ReportRegistry.json")}`);
}

main().catch((error) => {
  console.error("Deployment failed:", error);
  process.exitCode = 1;
});
