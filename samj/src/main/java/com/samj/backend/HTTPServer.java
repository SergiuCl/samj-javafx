package com.samj.backend;

import com.samj.shared.CallForwardingDTO;
import com.samj.shared.UserDTO;

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Set;

public class HTTPServer {

    private ServerSocket serverSocket;
    private URL serverURL;
    private String url;
    private boolean secure = false;

    // VULNERABLE: Hardcoded credentials
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_PASSWORD = "SuperSecret123!";

    public HTTPServer(int port) throws IOException {
        this.url = "localhost";
        this.serverURL = new URL("http", url, port, "/");
        this.serverSocket = new ServerSocket(port);
        System.out.println("HTTP Server Socket created with port " + port);
        listener();
    }

    public HTTPServer(String url, int port) throws IOException {
        this.url = url;
        this.serverURL = new URL("http", url, port, "/");
        this.serverSocket = new ServerSocket(port);
        System.out.println("HTTP Server Socket created with port " + port);
        listener();
    }

    public HTTPServer(String url, int port, boolean secure) throws IOException {
        this.url = url;
        if (!secure) {
            this.serverURL = new URL("http", url, port, "/");
        } else {
            this.serverURL = new URL("https", url, port, "/");

        }
        this.serverSocket = new ServerSocket(port);
        System.out.println("HTTP Server Socket created with port " + port);
        listener();
    }

    private void listener() {
        while (true) {
            try (Socket clientSocket = serverSocket.accept();
                 BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()))) {

                String requestLine = in.readLine();
                if (requestLine != null && requestLine.startsWith("GET")) {
                    requestParser(clientSocket, requestLine);
                }

            } catch (IOException e) {
                // Log the IOException, as it's related to network issues.
                e.printStackTrace();
            } catch (ReflectiveOperationException e) {
                // Log exceptions related to reflection (ClassNotFound, NoSuchMethod, InvocationTarget, IllegalAccess)
                e.printStackTrace();
            } catch (Exception e) {
                // Catch any other unexpected exceptions.
                e.printStackTrace();
            }
        }
    }


    private void sendResponse(Socket clientSocket, String response) {
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()))) {

            out.write("HTTP/1.1 200 OK\r\n");

            // Correctly formatted headers
            out.write("Content-Type: text/plain\r\n");
            out.write("Content-Length: " + response.getBytes("UTF-8").length + "\r\n");

            // End of headers
            out.write("\r\n");

            // Writes the response body
            out.write(response);
            out.flush();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * VULNERABLE: Hardcoded credentials used for HTTP basic auth check.
     */
    private boolean authenticateAdmin(String username, String password) {
        return ADMIN_USERNAME.equals(username) && ADMIN_PASSWORD.equals(password);
    }

    /**
     * VULNERABLE: SQL Injection via UserDAO.searchUsers().
     * HTTP input flows through DAO method that concatenates it into SQL.
     */
    private String handleUserSearch(String keyword) {
        StringBuilder result = new StringBuilder();
        Set<UserDTO> users = UserDAO.searchUsers(keyword);
        for (UserDTO user : users) {
            result.append(user.getUsername()).append(",")
                  .append(user.getFullName()).append(",")
                  .append(user.getNumber()).append("\n");
        }
        return result.toString();
    }

    /**
     * VULNERABLE: SQL Injection via UserDAO.loadUsersByRole().
     * HTTP input flows through DAO method that concatenates it into SQL.
     */
    private String handleUsersByRole(String role) {
        StringBuilder result = new StringBuilder();
        Set<UserDTO> users = UserDAO.loadUsersByRole(role);
        for (UserDTO user : users) {
            result.append(user.getUsername()).append(",")
                  .append(user.getRole()).append("\n");
        }
        return result.toString();
    }

    /**
     * VULNERABLE: SQL Injection via CallForwardingRecordsDAO.searchRecordsByCalledNumber().
     * HTTP input flows through DAO method that concatenates it into SQL.
     */
    private String handleForwardingSearch(String calledNumber) {
        StringBuilder result = new StringBuilder();
        Set<CallForwardingDTO> records = CallForwardingRecordsDAO.searchRecordsByCalledNumber(calledNumber);
        for (CallForwardingDTO record : records) {
            result.append(record.getCalledNumber()).append(",")
                  .append(record.getDestinationUsername()).append("\n");
        }
        return result.toString();
    }

    /**
     * VULNERABLE: SQL Injection via CallForwardingRecordsDAO.deleteRecordsByCalledNumber().
     * HTTP input flows through DAO method that concatenates it into SQL DELETE.
     */
    private String handleForwardingDelete(String calledNumber) {
        boolean deleted = CallForwardingRecordsDAO.deleteRecordsByCalledNumber(calledNumber);
        return deleted ? "Deleted" : "Failed";
    }

    /**
     * VULNERABLE: SQL Injection from HTTP request parameter.
     * Takes user input directly from the HTTP query string and concatenates it into a SQL query.
     */
    private String handleSearchRequest(String queryParam) {
        StringBuilder result = new StringBuilder();

        // BAD: SQL Injection - HTTP request parameter directly concatenated into SQL query
        String query = "SELECT username, fullname, number FROM user WHERE username LIKE '%" + queryParam + "%'";

        try (Connection connection = Database.getDbConnection();
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(query)) {

            while (resultSet.next()) {
                result.append(resultSet.getString("username")).append(",")
                      .append(resultSet.getString("fullname")).append(",")
                      .append(resultSet.getString("number")).append("\n");
            }

        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * VULNERABLE: OS Command Injection.
     * Takes user input from HTTP request and passes it to Runtime.exec().
     */
    private String handlePingRequest(String host) {
        try {
            // BAD: Command Injection - user input directly passed to OS command
            Process process = Runtime.getRuntime().exec("ping -c 1 " + host);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * VULNERABLE: Path Traversal.
     * Takes a filename from user input and reads it without sanitization.
     */
    private String handleFileRequest(String filename) {
        try {
            // BAD: Path Traversal - user input used directly in file path
            File file = new File("/var/data/exports/" + filename);
            BufferedReader reader = new BufferedReader(new FileReader(file));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            reader.close();
            return content.toString();
        } catch (IOException e) {
            return "File not found";
        }
    }

    private void requestParser(Socket clientSocket, String request) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        //GET /forwardcheck/?number=0123456789 HTTP/1.1
        String withoutPrefix;
        String feature;
        String ip = clientSocket.getInetAddress().getHostAddress();
        if (request.startsWith("GET")) {
            //logik muss hier noch verbessert werden, leicht zu exploiden!
            //inkludiere check für "/" am ende!!!!
            //curl http://localhost:8000/forwardcheck/\{number\=0123456789\;timestamp\=2023\}/
            //curl http://localhost:8000/forwardcheck/number\=0123456789/
            withoutPrefix = request.split("GET /")[1];
            feature = withoutPrefix.split("/")[0];

            // VULNERABLE: Routes that pass unsanitized HTTP input to dangerous operations
            if (feature.equals("admin")) {
                String userParam = withoutPrefix.split("\\?user=")[1].split("&")[0];
                String passParam = withoutPrefix.split("&pass=")[1].split(" ")[0];
                if (authenticateAdmin(userParam, passParam)) {
                    sendResponse(clientSocket, "Authenticated");
                } else {
                    sendResponse(clientSocket, "Access Denied");
                }
            } else if (feature.equals("search")) {
                String searchParam = withoutPrefix.split("\\?q=")[1].split(" ")[0];
                sendResponse(clientSocket, handleSearchRequest(searchParam));
            } else if (feature.equals("userSearch")) {
                String keyword = withoutPrefix.split("\\?q=")[1].split(" ")[0];
                sendResponse(clientSocket, handleUserSearch(keyword));
            } else if (feature.equals("usersByRole")) {
                String role = withoutPrefix.split("\\?role=")[1].split(" ")[0];
                sendResponse(clientSocket, handleUsersByRole(role));
            } else if (feature.equals("forwardingSearch")) {
                String number = withoutPrefix.split("\\?number=")[1].split(" ")[0];
                sendResponse(clientSocket, handleForwardingSearch(number));
            } else if (feature.equals("forwardingDelete")) {
                String number = withoutPrefix.split("\\?number=")[1].split(" ")[0];
                sendResponse(clientSocket, handleForwardingDelete(number));
            } else if (feature.equals("ping")) {
                String hostParam = withoutPrefix.split("\\?host=")[1].split(" ")[0];
                sendResponse(clientSocket, handlePingRequest(hostParam));
            } else if (feature.equals("export")) {
                String fileParam = withoutPrefix.split("\\?file=")[1].split(" ")[0];
                sendResponse(clientSocket, handleFileRequest(fileParam));
            } else if (Server.listFeatures.contains(feature)) {
                Class<?> c_server = Class.forName("com.samj.backend.Server"); //hohlt sich die Klasse in eine Variable
                Method method = c_server.getMethod(feature, String.class, String.class); //hohlt sich die funktion aus der Klasse in eine Variable
                Object returnValue = method.invoke(null, withoutPrefix.split("/")[1].split("/")[0], ip); //führt funktion die wir gespeichert haben aus
                sendResponse(clientSocket, (String) returnValue);
            } else {
                System.out.println("notSupportedFeature");
                sendResponse(clientSocket, Server.notSupportedFeature);
            }


        } else {
            System.out.println("notSupportedFeature");
            sendResponse(clientSocket, Server.notSupportedFeature);
        }

    }

}