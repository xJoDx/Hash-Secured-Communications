package com.example.requestsender;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.android.volley.AuthFailureError;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.HurlStack;
import com.android.volley.toolbox.Volley;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

public class MainActivity extends AppCompatActivity {

    //region Variables declaration
    ArrayList<Host> hosts = new ArrayList<>(); //Local list of the saved hosts
    String targetA = "https://192.168.0.17:5000/hostA"; //URL of one host
    String targetB = "https://192.168.0.17:5000/hostB"; //URL of another host
    TextView communicationText; //Initialization fo the TextView that will be used to communicate with the user
    private String hostsFile = "hosts.txt"; //Log/Database file used for hosts persistence when the app is closed
    private String systemLogFile = "applog.txt"; //Log file used for debugging
    private String connexLogFile = "connlog.txt"; //Log file used to save all connexion related events
    private String filesPath = "dataSource"; //Folder in which the log and database files are stored
    File externalHostsFile; //Initialization of the database file
    File externalLogFile; //Initialization of the log file (its value will change depending on which kind of log is necessary)
    //endregion

    //region Network ToolBox
    /* FUNCTION: getHostnameVerifier.verify(String hostname, SSLSession session
    *  RETURNS: Boolean
    *  PARAMETERS:
    *       - String hostname: hostname that should be matched by the server
    *       - SSLSession session: current connexion session
    *
    *  AIM: Checks that the hostname of the established connection and the one on the certificate are the same
    *
    *  PROBLEMS ENCOUNTERED: Even though the hostname is valid (192.168.0.17), the return value of
    *  (session.getPeerHost() == hostname) was always "false".
    *
    *  PROBLEMS RESOLUTION: Although not a good security practice, the function was set to always return "true"
    * */
    private HostnameVerifier getHostnameVerifier() {
        return new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();

                //Initial return statement causing an SSLException to be thrown
                //return (session.getPeerHost() == hostname);

                //Debug tentative to identify the problem, but it only showed that the hostnames were the same
                //Log.d("HOSTVERIF","VERIFHOST: " + session.getPeerHost());
                //Log.d("HOSTVERIF","HOSTNAME: " + hostname);
                return true;
            }
        };
    }

    /* FUNCTION: mResponseListener.onResponse(secureRequests.secureResponse response)
    *  RETURNS: void
    *  PARAMETERS:
    *       - secureRequests.secureResponse response: response given by the server
    *
    *  AIM: Handle the response to the request from the server to assess the security status of the
    *  communication
    *
    *  OUTPUT: Displays the result of the security assessment and logs it into a text file.
    *
    *  PROCESS:
    *       1. Get the "X-Checksum" header from the response
    *       2. Call the function "Evaluate" and store its result in the boolean "legitimate"
    *       3. If the response IS meeting the security requirements, its content is examined
    *           A. If the server replied normally to the request, the user is informed through the use
    *              of the "communicationText" communicationText, and the event is logged internally.
    *           B. If the server denied us access to the content because the client request WAS NOT
    *              meeting the security requirements, the user is informed through the use of the
    *              "communicationText" communicationText, and the event is logged internally.
    *       4. If the response IS NOT meeting the security requirements
    *           A. The user is warned through the use of the "communicationText" TextView
    *           B. The incident is logged internally so that an investigator could assess the security
    *              of the connexion if forensics investigations are necessary
    */
    public Response.Listener<secureRequests.secureResponse> mResponseListener = new Response.Listener<secureRequests.secureResponse>() {
        @Override
        public void onResponse(secureRequests.secureResponse response) {
            String localChecksum = "";
            Boolean legitimate = false;
            localChecksum = response.getHeaders().get("X-Checksum"); // STEP 1
            legitimate = Evaluate(localChecksum, response.getOriginHost()); // STEP 2
            response.getOriginHost().IncrementNbPacket();
            if(legitimate) { //STEP 3
                if(response.getResponseBody().contains("GRANTED")) { //STEP 3.A
                    String connexionInfo =
                            nowTime() + " - " + response.getOriginHost().getRemoteAddress() +
                            " - VALIDATED US at " + response.getOriginHost().getNbPacket().toString() + " packets!";
                    updateHostDatabaseEntry(getApplicationContext(), response.getOriginHost());
                    logConnexion(false, false, connexionInfo);
                }
                else{ //STEP 3.B
                    String connexionInfo =
                            nowTime() + " - " + response.getOriginHost().getRemoteAddress() +
                            " - REJECTED US at " + response.getOriginHost().getNbPacket().toString() + " packets!";
                    logConnexion(true, true, connexionInfo);
                }
                communicationText.setText(response.getResponseBody());
            }
            else{ //STEP 4
                String connexionInfo =
                        nowTime() + response.getOriginHost().getRemoteAddress() +
                        " - ISSUED A WRONG CHECKSUM at " + response.getOriginHost().getNbPacket().toString() + " packets!";
                logConnexion(true, false, connexionInfo);
                communicationText.setText("WARNING: The connection is unsafe, the host did not give the correct hash !");
            }
        }
    };

    /* FUNCTION: mErrorListener.onErrorResponse(VolleyError error)
    *  RETURNS: void
    *  PARAMETERS:
    *       - VolleyError error: the error raised by onResponse
    *
    *  AIM: Handle the case of a connexion error
    *
    *  OUTPUT: Warns the user of the appearance of an error through the "communicateText" TextView and logs its content
    *  in the internal log file.
    */
    public Response.ErrorListener mErrorListener = new Response.ErrorListener() {
        @Override
        public void onErrorResponse(VolleyError error) {
            communicationText.setText("AN ERROR OCCURED: " + error.getMessage());
            logEvent("Error", error.getMessage());
        }
    };
    //endregion

    //region Utilities
    /* FUNCTION: nowTime()
     * RETURNS: String
     *
     * AIM: Get the current time (up to the seconds) in a string format.
     */
    private String nowTime() {
        return java.text.DateFormat.getDateTimeInstance().format(new Date());
    }

    /* FUNCTION: Evaluate(String checksum, Host host)
     * RETURNS: Boolean
     * PARAMETERS:
     *      - String checksum: the checksum provided by the server
     *      - Host host: the host which sent the request
     *
     * AIM: Compare the checksum received from the server with the one that should be generated by
     * the host (hence the call to generateHash())
     */
    private Boolean Evaluate(String checksum, Host host){
        return(checksum.equals(host.generateHash()));
    }

    /* FUNCTION: isExternalStorageReadOnly()
     * RETURNS: Boolean
     *
     * AIM: Detect if the storage is in read-only mode, and return the result of this assessment.
     */
    private static boolean isExternalStorageReadOnly() {
        String extStorageState = Environment.getExternalStorageState();
        if (Environment.MEDIA_MOUNTED_READ_ONLY.equals(extStorageState)) {
            return true;
        }
        return false;
    }

    /* FUNCTION: isExternalStorageAvailable()
     * RETURNS: Boolean
     *
     * AIM: Assess if the external storage (not the SD card, but the storage which can be accessed
     * by other apps or users). Return the result of this assessment
     */
    private static boolean isExternalStorageAvailable() {
        String extStorageState = Environment.getExternalStorageState();
        if (Environment.MEDIA_MOUNTED.equals(extStorageState)) {
            return true;
        }
        return false;
    }
    //endregion

    //region Log
    /* FUNCTION: logConnexion(boolean isError, boolean isOutbound, String connexionDetails)
     * RETURNS: Boolean
     * PARAMETERS:
     *      - boolean isError: if the event to be looged is an error
     *      - boolean isOutbound: if the event to be logged concerns a packet sent from the client to the server
     *      - String connexionDetails: the details of connexion (date and time, connexion refused, access granted...)
     *
     * AIM: Log into the connexLogFile (connlog.txt) all the events, with their date and time, related to the connexion
     * with the hosts
     *
     * PROCESS:
     *      1. Depending on the type of log (error, outbound...), some prefixes are added to the string "toWrite",
     *         which will be the one used to write in the file
     *      2. The details (date, time, status of connexion) are added to the main string
     *      3. Make sure that the external storage is available and writeable
     *      4. Writing in the file with a FileOutputStream (filesPath = dataSource, connexLogFile = "connlog.txt", APPEND)
     *      5. Returns true if all of the above succeeded
     */
    private Boolean logConnexion(boolean isError, boolean isOutbound, String connexionDetails){
        String toWrite = "\n";
        boolean written = false;
        //STEP 1
        if(isError) { toWrite += "[ERR - "; }
        else{ toWrite += "[INF - "; }
        if(isOutbound){ toWrite += "C>O] "; }
        else{ toWrite += "C<I] "; }
        //END OF STEP1
        toWrite += connexionDetails; //STEP 2

        if(isExternalStorageAvailable() && !(isExternalStorageReadOnly())) { //STEP 3
            externalLogFile = new File(getExternalFilesDir(filesPath), connexLogFile);
            try {
                //STEP 4
                FileOutputStream toLogStream = new FileOutputStream(externalLogFile, true);
                toLogStream.write(toWrite.getBytes());
                toLogStream.close();
                //END OF STEP 4
                written = true;

            } catch (Exception e) {
                logEvent("Error", e.toString());
            }
        }
        return written; //STEP 5
    }

    /* FUNCTION: logEvent(String eventType, String connexionDetails)
     * RETURNS: void
     * PARAMETERS:
     *      - String eventType: Type of the event (Error, Information...)
     *      - String connexionDetails: the details of the event (date and time, error/custom message...)
     *
     * AIM: Log into the systemLogFile (applog.txt) all the events, with their date and time, related to the
     * application itself (exceptions, files not being founds...)
     *
     * PROCESS:
     *      1. Depending on the type of log (error, information...), some prefixes are added to the string "toWrite",
     *         which will be the one used to write in the file
     *      2. The details (date, time, error message) are added to the main string
     *      3. Make sure that the external storage is available and writeable
     *      4. Writing in the file with a FileOutputStream (filesPath = dataSource, connexLogFile = "applog.txt", APPEND)
     */
    private void logEvent(String eventType, String eventContent){
        String toWrite = "\n";
        if(eventType.equals("Error")) { toWrite += "[E] - "; } //STEP 1
        else{ toWrite += "[I] - "; }
        toWrite += nowTime() + " - ";
        toWrite += eventContent; //STEP 2

        if(isExternalStorageAvailable() && !(isExternalStorageReadOnly())) { //STEP 3
            externalLogFile = new File(getExternalFilesDir(filesPath), systemLogFile);
            try {
                //STEP 4
                FileOutputStream toLogStream = new FileOutputStream(externalLogFile, true);
                toLogStream.write(toWrite.getBytes());
                toLogStream.close();
                //END OF STEP 4

            } catch (Exception e) {
                Log.e("Main Error", e.toString());
            }
        }
    }
    //endregion

    //region Persistence
    /*
        All the functions in this region allow the application to have persistence.
        This persistence allows the user to close the application and start it again while still
        being able to connect securely and reliably with the hosts. The persistence is maintained
        even if the mobile device is restarted.

        The structure of each line in the "hosts.txt" file is the following:
        [HOST EXACT ADDRESS];[TIME OF THE FIRST PACKET SENT];[PACKET NUMBER EXPECTED ON THE NEXT RESPONSE]
        The host exact address (complete URL) was used in this experimentation as it was not possible to
        handle different IPs. The two hosts (https://192.168.0.17:5000/[hostA||hostB]) actually represent
        two different webservers.
     */

    /* FUNCTION: getHostsFromFile(Context context)
     * RETURNS: ArrayList<Host>
     * PARAMETERS:
     *      - Context context: context of the application
     *
     * AIM: Retrieve the hosts from the file "hosts.txt"
     *
     * PROCESS:
     *      1. Check if the external storage is available
     *      2. If the hosts file does not exists, create it
     *          A. Check if the external storage is writeable
     *          B. Write nothing in the file with a FileOutputStream and a FileWriter to create it
     *      3. Create the necessary components to read and save the content of the hosts.txt file
     *      4. Prepare the information of each line to create the Host instances
     *          A. Check that the line is not null (which would mean the reader reached the end of the file)
     *          B. Splits the line under the ";" character (used to separate a Host attributes)
     *          C. Check that there are more than 2 elements (to prevent empty lines or incomplete information)
     *          D. Creates an instance of the Host class with the given parameters
     *          E. Add this instance to the list of hosts
     *      5. Return the hosts list
     */
    private ArrayList<Host> getHostsFromFile(Context context){
        ArrayList<Host> hostsListFromFile = new ArrayList<>();
        try{
            if(isExternalStorageAvailable()) { //STEP 1
                if(!(externalHostsFile.exists())){ //STEP 2
                    if(isExternalStorageAvailable() && !(isExternalStorageReadOnly())) { //STEP 2.A
                        try {
                            //STEP 2.B
                            FileOutputStream toHostsFile = new FileOutputStream(externalLogFile, true);
                            FileWriter writer = new FileWriter(externalHostsFile);
                            writer.write("");
                            writer.close();
                            toHostsFile.close();
                            //END OF STEP 2.B
                        } catch (Exception e) {
                            logEvent("Error", e.toString());
                        }
                    }
                }
                //STEP 3
                FileInputStream fis = new FileInputStream(externalHostsFile);
                if (null != fis) {
                    InputStreamReader hostsFileReader = new InputStreamReader(fis);
                    BufferedReader hostsFileBuffReader = new BufferedReader(hostsFileReader);
                    String line = "";
                    //END OF STEP 3

                    while ((line = hostsFileBuffReader.readLine()) != null) { //STEP 4.A
                        String[] tempContent = line.split(";"); //STEP 4.B
                        if(tempContent.length >=2) { //STEP 4.C
                            Host tempHost = new Host(tempContent[0], tempContent[1], (Integer.parseInt(tempContent[2]) - 2)); //STEP 4.D
                            hostsListFromFile.add(tempHost); //STEP 4.E
                        }
                    }

                    fis.close();
                }
            }
            else{
                logEvent("Info", "External Storage Not Available");
            }
        } catch (FileNotFoundException notFound) {
            logEvent("Error", notFound.toString());
        } catch (IOException ioE){
            logEvent("Error", ioE.toString());
        }
        return hostsListFromFile; //STEP 5
    }

    /* FUNCTION: addHostToDatabase(Context context, Host host)
     * RETURNS: boolean
     * PARAMETERS:
     *      - Context context: context of the running application
     *      - Host host: Instance of the Host class to be added to the "hosts.txt" file
     *
     * AIM: Add a line to the "hosts.txt" to represent a new host to be memorized
     *
     * PROCESS:
     *      1. Generate the string to be written (description available in the Host class)
     *      2. Check if the external storage is available and writeable
     *      3. Write the string as a new line at the end of the file (append: true)
     *      4. Return true if all of the above went without errors
     */
    private boolean addHostToDatabase(Context context, Host host){
        String toWrite = host.toStringForLog(); //STEP 1
        boolean written = false;
        if(isExternalStorageAvailable() && !(isExternalStorageReadOnly())) { //STEP 2
            try {
                //STEP 3
                FileWriter writer = new FileWriter(externalHostsFile, true);
                writer.write(toWrite);
                writer.close();
                written = true;
                //END OF STEP 3

            } catch (Exception e) {
                logEvent("Error", e.toString());
            }
        }
        else{
            logEvent("Info", "External Storage Not Available");
        }
        return written; //STEP 4
    }

    /* FUNCTION: updateHostDatabaseEntry(Context context, Host host)
     * RETURNS: void
     * PARAMETERS:
     *      - Context context: context of the running app
     *      - Host host: instance of the Host class which entry's will be updated in "hosts.txt"
     *
     * AIM: Update the entry for the host in the database to reflect the changes in the class
     * instance (new packet sent)
     *
     * PROCESS: This function rewrites the whole file to avoid extending the database, only modifying the desired line
     *      1. Check if the external storage is accessible and writeable
     *      2. Initialize the variables needed to read the database
     *      3. Search for the host which entry's will be updated and create the entry that will replace
     *         the old one
     *              A. Check the address of the entry against the host's one
     *              B. Add 2 to the number of the expected packet (+1 is the one the app is going to sent)
     *                 in the new entry
     *              C. Add the new entry to the string buffer, and declare that the program found the right line
     *              D. If another line with the same host address is found, do nothing
     *              E. If a line with an address differing from the host's address, append it to the string buffer
     *      4. Rewrite the whole file with the modified line
     */
    private void updateHostDatabaseEntry(Context context, Host host){
        try {
            if(isExternalStorageAvailable() && !(isExternalStorageReadOnly())) { //STEP 1
                FileInputStream hostsFileInput = new FileInputStream(externalHostsFile);

                if (null != hostsFileInput) {
                    //STEP 2
                    InputStreamReader hostsFileReader = new InputStreamReader(hostsFileInput);
                    BufferedReader hostsFileBuffReader = new BufferedReader(hostsFileReader);
                    StringBuffer strBuff = new StringBuffer();
                    String line = "";
                    Boolean found = false;
                    //END OF STEP 2

                    //STEP 3
                    while(!found){
                        line = hostsFileBuffReader.readLine();
                        if(!(null == line)){
                            if(line.split(";")[0].equals(host.getRemoteAddress())){ //STEP 3.A
                                Integer val = Integer.parseInt(line.split(";")[2]) + 2; //STEP 3.B
                                String vali = val.toString();
                                //STEP 3.C
                                String lino = line.split(";")[0] + ";" + line.split(";")[1] + ";" + vali + "\r";
                                strBuff.append(lino);
                                found = true;
                                //END OF STEP 3.C
                            }
                            else if(line.split(";")[0].equals(host.getRemoteAddress())) {} //STEP 3.D
                            else{ //STEP 3.E
                                strBuff.append(line.split(";")[0] + ";" + line.split(";")[1] + ";" + line.split(";")[2] + "\r");
                            }
                        }
                    }
                    hostsFileReader.close();
                    hostsFileInput.close();
                    //STEP 4
                    FileWriter hostWrite = new FileWriter(externalHostsFile, Boolean.FALSE);
                    Log.d("strBuff", strBuff.toString());
                    hostWrite.write(strBuff.toString());
                    hostWrite.close();
                    //END OF STEP 4
                }
            }
        } catch (Exception e) {
            logEvent("Error", e.toString());
        }
    }

    /* FUNCTION: purgeHosts()
     * RETURNS: void
     * PARAMETERS: none
     *
     * AIM: Empty the "hosts.txt" to reset the database, and clear the ArrayList hosts (hosts list)
     *
     * PROCESS:
     *      1. Create a new FileOutputStream with append set to false to replace the whole file
     *      2. Call the "flush" method of the FileOutputStream to clear the file's content
     *      3. Inform the user that the hosts list is now cleared
     */
    private void purgeHosts(){
        try {
            FileOutputStream purgingHosts = new FileOutputStream(externalHostsFile); //STEP 1
            //STEP 2
            purgingHosts.flush();
            purgingHosts.close();
            hosts.clear();
            //END OF STEP 2
            communicationText.setText("Hosts list cleared !"); //STEP 3
        } catch (FileNotFoundException e) {
            logEvent("Error", e.toString());
        } catch (IOException e){
            logEvent("Error", e.toString());
        }
    }
    //endregion

    //region Main
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        logEvent("Info", "Activity started"); //Log in the appLog that the activity started
        externalHostsFile = new File(getExternalFilesDir(filesPath), hostsFile);
        hosts = getHostsFromFile(this); //Get the list of hosts saved in "hosts.txt"

        //region Request Queue
        /* FUNCTION: createConnection(URL url)
         *
         * AIM: This function is used to override the hostname verifier, as an unexpected and unresolved
         * SSL error kept stopping the application from working.
         */
        HurlStack hurlStack = new HurlStack(){
            @Override
            protected HttpsURLConnection createConnection(URL url) throws IOException{
                HttpsURLConnection httpsURLConnection = (HttpsURLConnection) super.createConnection(url);
                try{
                    httpsURLConnection.setSSLSocketFactory(HttpsURLConnection.getDefaultSSLSocketFactory());
                    httpsURLConnection.setHostnameVerifier(getHostnameVerifier());
                } catch (Exception e){
                    e.printStackTrace();
                }
                return httpsURLConnection;
            }
        };

        RequestQueue requestQueue = Volley.newRequestQueue(MainActivity.this, hurlStack); //Initialization of the requestQueue with the modified hostname verifier
        //endregion

        //region User Interface Declaration
        /*
            In this region, all the Buttons, TextViews, EditTexts, and listeners are initialized.
            The EditText boxes are filled with the experimentation hosts to avoid having to type
            them each time the application is started.
         */
        Button btnGETtoA = findViewById(R.id.btn_GET_to_A);
        Button btnGETtoB = findViewById(R.id.btn_GET_to_B);
        Button btnPOSTtoA = findViewById(R.id.btn_POST_to_A);
        Button btnPOSTtoB = findViewById(R.id.btn_POST_to_B);
        Button btnPURGE = findViewById(R.id.btn_clear_hosts);
        communicationText = findViewById(R.id.communicationText);

        EditText ipAPlaceholder = findViewById(R.id.bxCompAIP);
        EditText ipBPlaceholder = findViewById(R.id.bxCompBIP);

        ipAPlaceholder.setText(targetA);
        ipBPlaceholder.setText(targetB);

        btnGETtoA.setOnClickListener(View -> clicked(Request.Method.GET, ipAPlaceholder.getText().toString(), requestQueue));
        btnGETtoB.setOnClickListener(View -> clicked(Request.Method.GET, ipBPlaceholder.getText().toString(), requestQueue));
        btnPOSTtoA.setOnClickListener(View -> clicked( Request.Method.POST, ipAPlaceholder.getText().toString(), requestQueue));
        btnPOSTtoB.setOnClickListener(View -> clicked( Request.Method.POST, ipBPlaceholder.getText().toString(), requestQueue));
        btnPURGE.setOnClickListener(View -> purgeHosts());
        //endregion
    }

    /* FUNCTION: clicked(Integer method, String targetHost, RequestQueue rq)
     * RETURNS: void
     * PARAMETERS:
     *      - Integer method: The method (GET/POST) that will be used for the request
     *      - String targetHost: Full URL of the distant host to send the request to(*)
     *      - RequestQueue rq: The RequestQueue object that will be used to send the request
     *  (*)Because of the difficulty to simulate different IPs in an experimental context, the "hostA"
     *     and "hostB" represent how two different webservers would behave in real life
     *
     * AIM: Generate and send the request to the selected host. Add the host to the database if it is
     * a new one.
     *
     * PROCESS:
     *      1. Check if the selected host exists in the list
     *      2. Add the host to the hosts list and to the database if the host is a new one
     *      3. Call the craftRequest function with the type of request (GET/POST) and the selected host
     *         as parameters
     *      4. Add the request to the queue (which sends it)
     */
    private void clicked(Integer method, String targetHost, RequestQueue rq) {
        Host localHost = new Host("");
        boolean firstPacket = false;

        //STEP 1
        for (Host test:hosts) {
            if(test.getRemoteAddress().equals(targetHost)){
                localHost = test;
                break;
            }
        }
        //END OF STEP 1

        //STEP 2
        if(localHost.getRemoteAddress().equals("")) {
            localHost = new Host(targetHost);
            hosts.add(localHost);
            addHostToDatabase(this, localHost);
            firstPacket = true;
        }
        //END OF STEP 2
        secureRequests secReq;
        secReq = craftRequest(method, localHost); //STEP 3
        rq.add(secReq); //STEP 4
    }

    /* FUNCTION: craftRequest(int mMethod, Host targetHost)
     * RETURNS: Instance of the secureRequests class
     * PARAMETERS:
     *      - int mMethod: The method (GET/POST) to be used in the request
     *      - Host targetHost: Instance of the Host class to which the request will be sent
     *
     * AIM: Create the secureRequests instance with the appropriate security headers
     *
     * PROCESS: Call the "generateHeaders" method of the target host to put it into the headers of the
     * request. Return the request
     */
    private secureRequests craftRequest(int mMethod, Host targetHost) {
        secureRequests mSecureRequest = new secureRequests(mMethod, targetHost, mResponseListener, mErrorListener) {
            @Override
            public Map<String, String> getHeaders() throws AuthFailureError {
                return targetHost.generateHeaders();
            }
        };
        return mSecureRequest;
    }
    //endregion
}