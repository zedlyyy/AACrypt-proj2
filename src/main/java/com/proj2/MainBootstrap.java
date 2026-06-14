package com.proj2;

import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Base64;

import javax.crypto.SecretKey;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.proj2.cryptoUtility.AesCtrCrypto;
import com.proj2.cryptoUtility.OpeCrypto;
import com.proj2.cryptoUtility.PaillierCrypto;
import com.proj2.cryptoUtility.RsaMultiplicativeCrypto;

public class MainBootstrap {

    //Helper class
    private static class BenchmarkStats {
        long totalNs = 0;
        long count = 0;

        void add(long durationNs) {
            totalNs += durationNs;
            count++;
        }

        double totalMs() {
            return totalNs / 1_000_000.0;
        }

        double avgMs() {
            if (count == 0) return 0.0;
            return (totalNs / 1_000_000.0) / count;
        }
    }


    public static void main(String[] args) {
        String csvFilePath = "src/main/java/com/proj2/Company-Employee.Database/Dataset-Emp-Database.csv";
        String indexFilePath = "client_index.json";

        try {
            long bootstrapStart = System.nanoTime();
            System.out.println("Starting Client Bootstrap...");

            //Benchmark classes
            BenchmarkStats aesDetStats = new BenchmarkStats();
            BenchmarkStats aesRndStats = new BenchmarkStats();
            BenchmarkStats opeStats = new BenchmarkStats();
            BenchmarkStats paillierStats = new BenchmarkStats();
            BenchmarkStats rsaStats = new BenchmarkStats();

            // Generate keys
            SecretKey deterministicKey = AesCtrCrypto.generateKey();
            SecretKey randomKey = AesCtrCrypto.generateKey();
            PaillierCrypto.KeyPair paillierKeys = PaillierCrypto.generateKeyPair(2048);
            RsaMultiplicativeCrypto.RsaKeyPair rsaKeys = RsaMultiplicativeCrypto.generateKeyPair(2048);
            OpeCrypto ope = new OpeCrypto();

            // Connect to DB
            System.out.println("Connecting to DB...");
            Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/company_db", "root", "password");
            Statement statement = connection.createStatement();

            // Create table
            statement.execute("DROP TABLE IF EXISTS encrypted_employees");
            String createTableQuery = "CREATE TABLE IF NOT EXISTS encrypted_employees (id INT AUTO_INCREMENT PRIMARY KEY, employeeID_DET TEXT, fullName_RND TEXT, fullName_DET TEXT, age_OPE BIGINT, departmentID_DET TEXT, salary_OPE BIGINT, salary_PAILLIER TEXT, salary_RSA TEXT, bonusEligibility_DET TEXT)";
            statement.execute(createTableQuery);
            System.out.println("DB structure successfully initialized!");
            
            // Fill table with .csv values
            System.out.println("Inserting dataset...");
            FileReader fileReader = new FileReader(csvFilePath);

            Iterable<CSVRecord> records = CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build().parse(fileReader);
            String insertValuesQuery = "INSERT INTO encrypted_employees (employeeID_DET, fullName_RND, fullName_DET, age_OPE, departmentID_DET, salary_OPE, salary_PAILLIER, salary_RSA, bonusEligibility_DET) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
            
            PreparedStatement preparedStatement = connection.prepareStatement(insertValuesQuery);
            int rowCount = 0;

            for (CSVRecord record : records) {
                String empID = record.get("employeeID");
                String fullName = record.get("Full Name");
                int age = Integer.parseInt(record.get("Age"));
                String deptID = record.get("DepartmentID");
                int salary = Integer.parseInt(record.get("Salary"));
                String bonusEligibility = record.get("BonusEligibiity");

                long t0, t1;

                t0 = System.nanoTime();
                String encEmpID = AesCtrCrypto.encryptDeterministic(empID, deterministicKey);
                t1 = System.nanoTime();
                aesDetStats.add(t1 - t0);

                t0 = System.nanoTime();
                String encFullName = AesCtrCrypto.encrypt(fullName, randomKey);
                t1 = System.nanoTime();
                aesRndStats.add(t1 - t0);

                t0 = System.nanoTime();
                String encFullNameDeterministic = AesCtrCrypto.encryptDeterministic(fullName, deterministicKey);
                t1 = System.nanoTime();
                aesDetStats.add(t1 - t0);

                t0 = System.nanoTime();
                long opeAge = ope.encrypt(age);
                t1 = System.nanoTime();
                opeStats.add(t1 - t0);

                t0 = System.nanoTime();
                String encDeptID = AesCtrCrypto.encryptDeterministic(deptID, deterministicKey);
                t1 = System.nanoTime();
                aesDetStats.add(t1 - t0);

                t0 = System.nanoTime();
                long opeSalary = ope.encrypt(salary);
                t1 = System.nanoTime();
                opeStats.add(t1 - t0);

                t0 = System.nanoTime();
                BigInteger paillierSalary = PaillierCrypto.encrypt(salary, paillierKeys.publicKey);
                t1 = System.nanoTime();
                paillierStats.add(t1 - t0);

                t0 = System.nanoTime();
                BigInteger rsaSalary = RsaMultiplicativeCrypto.encrypt(salary, rsaKeys.publicKey);
                t1 = System.nanoTime();
                rsaStats.add(t1 - t0);

                t0 = System.nanoTime();
                String encBonusEligibility = AesCtrCrypto.encryptDeterministic(bonusEligibility, deterministicKey);
                t1 = System.nanoTime();
                aesDetStats.add(t1 - t0);

                preparedStatement.setString(1, encEmpID);
                preparedStatement.setString(2, encFullName);
                preparedStatement.setString(3, encFullNameDeterministic);
                preparedStatement.setLong(4, opeAge);
                preparedStatement.setString(5, encDeptID);
                preparedStatement.setLong(6, opeSalary);
                preparedStatement.setString(7, paillierSalary.toString());
                preparedStatement.setString(8, rsaSalary.toString());
                preparedStatement.setString(9, encBonusEligibility);

                preparedStatement.executeUpdate();
                rowCount++;
            }
            fileReader.close();
            System.out.println("Successfully encrypted values and inserted them into DB.");
            System.out.println("Rows inserted: " + rowCount);

            System.out.println();

            System.out.println("=== ENCRYPTION TIME BENCHMARKS ===");
            System.out.printf("AES/CTR deterministic:  total=%.3f ms, operations=%d, avg=%.6f ms/op%n",
                    aesDetStats.totalMs(), aesDetStats.count, aesDetStats.avgMs());

            System.out.printf("AES/CTR randomized:     total=%.3f ms, operations=%d, avg=%.6f ms/op%n",
                    aesRndStats.totalMs(), aesRndStats.count, aesRndStats.avgMs());

            System.out.printf("OPE:                    total=%.3f ms, operations=%d, avg=%.6f ms/op%n",
                    opeStats.totalMs(), opeStats.count, opeStats.avgMs());

            System.out.printf("Paillier 2048-bit:      total=%.3f ms, operations=%d, avg=%.6f ms/op%n",
                    paillierStats.totalMs(), paillierStats.count, paillierStats.avgMs());

            System.out.printf("RSA 2048-bit:           total=%.3f ms, operations=%d, avg=%.6f ms/op%n",
                    rsaStats.totalMs(), rsaStats.count, rsaStats.avgMs());
            System.out.println("==================================");
            System.out.println();

 
            System.out.println("Saving client index...");
            ClientIndex index = new ClientIndex();
            index.deterministicKeyBase64 = Base64.getEncoder().encodeToString(deterministicKey.getEncoded());
            index.randomKeyBase64 = Base64.getEncoder().encodeToString(randomKey.getEncoded());
            index.paillierKeyPair = paillierKeys;
            index.rsaKeyPair = rsaKeys;
            index.ope = ope;

            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            try (FileWriter fileWriter = new FileWriter(indexFilePath)) {
                gson.toJson(index, fileWriter);
            }

            System.out.println("Client index saved!");
            System.out.println();
            preparedStatement.close();
            statement.close();
            connection.close();
            
            //Benchmarks
            long bootstrapEnd = System.nanoTime();

            double bootstrapLatencyMs = (bootstrapEnd - bootstrapStart) / 1_000_000.0;
            double bootstrapLatencySeconds = bootstrapLatencyMs / 1000.0;

            System.out.println("=== BOOTSTRAP TIME BENCHMARKS ===");
            System.out.printf("BOOTSTRAP LATENCY IN MS=%.3f%n", bootstrapLatencyMs);
            System.out.printf("BOOTSTRAP LATENCY IN SECONDS=%.3f%n", bootstrapLatencySeconds);
            System.out.println("=================================");
            System.out.println();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
