package com.proj2;

import java.io.FileReader;
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;
import com.proj2.cryptoUtility.AesCtrCrypto;
import com.proj2.cryptoUtility.PaillierCrypto;
import com.proj2.cryptoUtility.RsaMultiplicativeCrypto;

public class MainQueryProcessor {

    private static ClientIndex clientIndex;
    private static SecretKey deterministicKey;
    private static SecretKey randomKey;
    private static Connection connection;

    public static void main(String[] args) {
        String indexFilePath = "client_index.json";

        try {
            System.out.println("Initializing Query Processor");

            Gson gson = new Gson();
            try (FileReader reader = new FileReader(indexFilePath)) {
                clientIndex = gson.fromJson(reader, ClientIndex.class);
            }

            byte[] detKeyBytes = Base64.getDecoder().decode(clientIndex.deterministicKeyBase64);
            deterministicKey = new SecretKeySpec(detKeyBytes, "AES");

            byte[] rndKeyBytes = Base64.getDecoder().decode(clientIndex.randomKeyBase64);
            randomKey = new SecretKeySpec(rndKeyBytes, "AES");

            connection = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/company_db?allowPublicKeyRetrieval=true&useSSL=false", "root",
                    "password");

            // op1
            runSearchByEmployeeID("EMP1005");
            // op2
            runSearchByName("Emma Johnson");
            // op3
            runListEmployeesOrderedBySalary();
            // op4
            runSearchByDepartment("DPT109");
            // op5
            runFindHighestSalaryEmployee();
            // op6
            runCompareSalaries("Olivia Thomas", "James Jackson");
            // op7
            runListEmployeesOrderedByAge();
            // op8
            runUSDollarConversion("EMP1001");
            // op9
            runDepartmentSalarySum("DPT109");
            // op10
            runFindOldestEmployee();
            // op11
            runBonusCalculation();

            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void printAllInfo(ResultSet res) throws Exception {
        String plaintextID = AesCtrCrypto.decryptDeterministic(res.getString("employeeID_DET"), deterministicKey);
        String plaintextName = AesCtrCrypto.decrypt(res.getString("fullName_RND"), randomKey);
        int plaintextAge = clientIndex.ope.decrypt(res.getLong("age_OPE"));
        String plaintextDepartment = AesCtrCrypto.decryptDeterministic(res.getString("departmentID_DET"),
                deterministicKey);
        int plaintextSalary = clientIndex.ope.decrypt(res.getLong("salary_OPE"));
        String plaintextBonusEligibility = AesCtrCrypto.decryptDeterministic(res.getString("bonusEligibility_DET"),
                deterministicKey);

        System.out.println("Employee ID: " + plaintextID);
        System.out.println("Full Name: " + plaintextName);
        System.out.println("Age: " + plaintextAge);
        System.out.println("Department: " + plaintextDepartment);
        System.out.println("Salary: " + plaintextSalary);
        System.out.println("Bonus Eligibility: " + plaintextBonusEligibility);
    }

    // op 1
    private static void runSearchByEmployeeID(String empID) throws Exception {
        System.out.println("Running a search on employee ID: " + empID);

        String encryptedEmployeeID = AesCtrCrypto.encryptDeterministic(empID, deterministicKey);

        String sqlQuery = "SELECT * FROM encrypted_employees WHERE employeeID_DET = ?";
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, encryptedEmployeeID);
            try (ResultSet res = preparedStatement.executeQuery()) {
                if (res.next()) {
                    printAllInfo(res);
                } else {
                    System.out.println("No matches were found");
                }
            }
        }
    }

    // op 2
    private static void runSearchByName(String empName) throws Exception {
        System.out.println("Running a search on " + empName);

        String encryptedEmployeeName = AesCtrCrypto.encryptDeterministic(empName, deterministicKey);

        String sqlQuery = "SELECT * FROM encrypted_employees WHERE fullName_DET = ?";
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, encryptedEmployeeName);
            try (ResultSet res = preparedStatement.executeQuery()) {
                if (res.next()) {
                    printAllInfo(res);
                } else {
                    System.out.println("No matches were found");
                }
            }
        }
    }

    // op 3
    private static void runListEmployeesOrderedBySalary() throws Exception {
        System.out.println("Listing Employees by Salary");

        String sqlQuery = "SELECT fullName_RND, salary_OPE FROM encrypted_employees ORDER BY salary_OPE DESC";
        try (Statement statement = connection.createStatement(); ResultSet res = statement.executeQuery(sqlQuery)) {
            while (res.next()) {
                String plaintextName = AesCtrCrypto.decrypt(res.getString("fullName_RND"), randomKey);
                int plaintextSalary = clientIndex.ope.decrypt(res.getLong("salary_OPE"));
                System.out.println(plaintextName + ", " + plaintextSalary);
            }
        }
    }

    // op 4
    private static void runSearchByDepartment(String departmentID) throws Exception {
        System.out.println("Searching for employees in department ID: " + departmentID);

        String encryptedDepartment = AesCtrCrypto.encryptDeterministic(departmentID, deterministicKey);

        String sqlQuery = "SELECT employeeID_DET, fullName_RND FROM encrypted_employees WHERE departmentID_DET = ?";
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, encryptedDepartment);
            try (ResultSet res = preparedStatement.executeQuery()) {
                int employeeCounter = 0;
                while (res.next()) {
                    String plaintextEmpID = AesCtrCrypto.decryptDeterministic(res.getString("employeeID_DET"),
                            deterministicKey);
                    String plaintextName = AesCtrCrypto.decrypt(res.getString("fullName_RND"), randomKey);
                    employeeCounter++;

                    System.out.println("Match number " + employeeCounter);
                    System.out.println("Employee ID: " + plaintextEmpID);
                    System.out.println("Full Name: " + plaintextName);
                }
            }
        }
    }

    // op 5
    private static void runFindHighestSalaryEmployee() throws Exception {
        System.out.println("Searching for the highest salary employee...");

        String sqlQuery = "SELECT fullName_RND, salary_OPE FROM encrypted_employees ORDER BY salary_OPE DESC LIMIT 1";
        try (Statement statement = connection.createStatement(); ResultSet res = statement.executeQuery(sqlQuery)) {
            if (res.next()) {
                String plaintextName = AesCtrCrypto.decrypt(res.getString("fullName_RND"), randomKey);
                int plaintextSalary = clientIndex.ope.decrypt(res.getLong("salary_OPE"));

                System.out.println("Highest paid employee:");
                System.out.println("Full Name: " + plaintextName);
                System.out.println("Salary: " + plaintextSalary);
            }
        }
    }

    // op 6
    private static void runCompareSalaries(String employeeName1, String employeeName2) throws Exception {
        System.out.println("Comparing salaries for " + employeeName1 + " and " + employeeName2);

        String encryptedName1 = AesCtrCrypto.encryptDeterministic(employeeName1, deterministicKey);
        String encryptedName2 = AesCtrCrypto.encryptDeterministic(employeeName2, deterministicKey);

        long opeSalary1 = 0;
        long opeSalary2 = 0;
        boolean found1 = false;
        boolean found2 = false;

        String sqlQuery = "SELECT fullName_DET, salary_OPE FROM encrypted_employees WHERE fullName_DET IN (?, ?)";
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, encryptedName1);
            preparedStatement.setString(2, encryptedName2);
            try (ResultSet res = preparedStatement.executeQuery()) {
                while (res.next()) {
                    String currentEncryptedName = res.getString("fullName_DET");
                    if (currentEncryptedName.equals(encryptedName1)) {
                        opeSalary1 = res.getLong("salary_OPE");
                        found1 = true;
                    }
                    if (currentEncryptedName.equals(encryptedName2)) {
                        opeSalary2 = res.getLong("salary_OPE");
                        found2 = true;
                    }

                }
            }
        }

        if (!found1 || !found2) {
            System.out.println("Something went wrong.");
            return;
        }

        //blind comparison
        if (opeSalary1 > opeSalary2)
            System.out.println(employeeName1 + " has a higher salary");
        else if (opeSalary2 > opeSalary1)
            System.out.println(employeeName2 + " has a higher salary");
        else
            System.out.println("Salaries are equal");
    }

    // op 7
    private static void runListEmployeesOrderedByAge() throws Exception {
        System.out.println("Listing Employees by Age");

        String sqlQuery = "SELECT fullName_RND, age_OPE FROM encrypted_employees ORDER BY age_OPE ASC";
        try (Statement statement = connection.createStatement(); ResultSet res = statement.executeQuery(sqlQuery)) {
            while (res.next()) {
                String plaintextName = AesCtrCrypto.decrypt(res.getString("fullName_RND"), randomKey);
                int plaintextAge = clientIndex.ope.decrypt(res.getLong("age_OPE"));
                System.out.println(plaintextName + ", " + plaintextAge);
            }
        }
    }

    // op 8
    private static void runUSDollarConversion(String employeeID) throws Exception {
        System.out.println("Employee " + employeeID + "salary conversion to dollar");

        String encID = AesCtrCrypto.encryptDeterministic(employeeID, deterministicKey);
        BigInteger salary = null;

        String sqlQuery = "SELECT salary_RSA FROM encrypted_employees WHERE employeeID_DET = ?";
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, encID);
            try (ResultSet res = preparedStatement.executeQuery()) {
                if (res.next())
                    salary = new BigInteger(res.getString("salary_RSA"));
            }
        }

        if (salary == null) {
            System.out.println("Employee does not exist in the database");
            return;
        }

        // illustrative €-$ exchange rate: 1.10, so represented as 11 int
        int conversionMultiplier = 11;
        BigInteger encryptedConversionMultiplier = RsaMultiplicativeCrypto.encrypt(conversionMultiplier,
                clientIndex.rsaKeyPair.publicKey);

        // blind multiplication E(m1) * E(m2) mod n = E(m1*m2)
        BigInteger rsaModulus = clientIndex.rsaKeyPair.publicKey.n;
        BigInteger homomorphicResult = salary.multiply(encryptedConversionMultiplier).mod(rsaModulus);

        BigInteger decryptedRes = RsaMultiplicativeCrypto.decrypt(homomorphicResult, clientIndex.rsaKeyPair.privateKey);
        double usdSalary = decryptedRes.doubleValue() / 10.0;

        System.out.println("Employee " + employeeID + " salary in dollars: " + usdSalary);
    }

    // op 9
    private static void runDepartmentSalarySum(String departmentID) throws Exception {
        System.out.println("Summing salaries from department " + departmentID);

        String encryptedDepartment = AesCtrCrypto.encryptDeterministic(departmentID, deterministicKey);
        List<BigInteger> encryptedSalaries = new ArrayList<>();

        String sqlQuery = "SELECT salary_PAILLIER FROM encrypted_employees WHERE departmentID_DET = ?";
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, encryptedDepartment);
            try (ResultSet res = preparedStatement.executeQuery()) {
                while (res.next())
                    encryptedSalaries.add(new BigInteger(res.getString("salary_PAILLIER")));
            }
        }

        if (encryptedSalaries.isEmpty()) {
            System.out.println("Department does not have employees or is inexistent");
            return;
        }

        BigInteger n = clientIndex.paillierKeyPair.publicKey.n;
        BigInteger nSquared = n.multiply(n);
        BigInteger homomorphicProductResult = BigInteger.ONE;

        for (BigInteger cipher : encryptedSalaries) {
            homomorphicProductResult = homomorphicProductResult.multiply(cipher).mod(nSquared);
        }

        int decryptedTotalSalary = PaillierCrypto
                .decrypt(homomorphicProductResult, clientIndex.paillierKeyPair.privateKey).intValue();
        System.out.println("Total Department Salary Sum: " + decryptedTotalSalary);
    }

    // op 10
    private static void runFindOldestEmployee() throws Exception {
        System.out.println("Finding oldest employee...");

        String sqlQuery = "SELECT * FROM encrypted_employees ORDER BY age_OPE DESC LIMIT 1";
        try (Statement statement = connection.createStatement(); ResultSet res = statement.executeQuery(sqlQuery)) {
            if (res.next()) {
                printAllInfo(res);
            }
        }
    }

    // op 11
    private static void runBonusCalculation() throws Exception {
        System.out.println("Calculating 25% bonuses for bonus eligible employees");

        String encryptedBonusEligibility = AesCtrCrypto.encryptDeterministic("Yes", deterministicKey);
        BigInteger n = clientIndex.paillierKeyPair.publicKey.n;
        BigInteger nSquared = n.multiply(n);

        String sqlQuery = "SELECT fullName_RND, salary_PAILLIER FROM encrypted_employees WHERE bonusEligibility_DET = ?";
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, encryptedBonusEligibility);
            try (ResultSet res = preparedStatement.executeQuery()) {
                while (res.next()) {
                    String plaintextName = AesCtrCrypto.decrypt(res.getString("fullName_RND"), randomKey);
                    BigInteger salary = new BigInteger(res.getString("salary_PAILLIER"));

                    // blind multiplication
                    BigInteger serverBonus = salary.modPow(BigInteger.valueOf(25), nSquared);

                    int plaintextBonus = PaillierCrypto.decrypt(serverBonus, clientIndex.paillierKeyPair.privateKey)
                            .intValue();
                    double finalBonusValue = plaintextBonus / 100.0;

                    System.out.println(plaintextName + " is eligible for bonus awards of " + finalBonusValue);
                }
            }
        }
    }
}
