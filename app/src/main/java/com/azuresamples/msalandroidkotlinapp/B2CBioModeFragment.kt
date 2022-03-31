// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
package com.azuresamples.msalandroidkotlinapp

import android.content.Context
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import com.azuresamples.msalandroidkotlinapp.B2CBioConfiguration.getAuthorityFromPolicyName
import com.microsoft.identity.client.*
import com.microsoft.identity.client.IMultipleAccountPublicClientApplication.RemoveAccountCallback
import com.microsoft.identity.client.IPublicClientApplication.IMultipleAccountApplicationCreatedListener
import com.microsoft.identity.client.IPublicClientApplication.LoadAccountsCallback
import com.microsoft.identity.client.exception.MsalClientException
import com.microsoft.identity.client.exception.MsalException
import com.microsoft.identity.client.exception.MsalServiceException
import com.microsoft.identity.client.exception.MsalUiRequiredException
import kotlinx.android.synthetic.main.fragment_b2c_bio_mode.*
import kotlinx.android.synthetic.main.fragment_b2c_bio_mode.btn_acquireTokenSilently
import kotlinx.android.synthetic.main.fragment_b2c_bio_mode.btn_removeAccount
import kotlinx.android.synthetic.main.fragment_b2c_bio_mode.btn_runUserFlow
import kotlinx.android.synthetic.main.fragment_b2c_bio_mode.policy_list
import kotlinx.android.synthetic.main.fragment_b2c_bio_mode.txt_log
import kotlinx.android.synthetic.main.fragment_b2c_bio_mode.user_list
import kotlinx.android.synthetic.main.fragment_b2c_mode.*
import java.util.*

/**
 * Implementation sample for 'B2C' mode.
 */
class B2CBioModeFragment : Fragment() {
    /* UI & Debugging Variables */
    /*var removeAccountButton: Button? = null
    var runUserFlowButton: Button? = null
    var acquireTokenSilentButton: Button? = null
    var graphResourceTextView: TextView? = null
    var logTextView: TextView? = null
    var policyListSpinner: Spinner? = null
    var b2cUserList: Spinner? = null*/
    private var users: List<B2CBioUser>? = null

    /* Azure AD Variables */
    private var b2cApp: IMultipleAccountPublicClientApplication? = null

    private var theFrag = this
    private var userid = ""

    private lateinit var biometricPrompt: BiometricPrompt
    private var cryptographyManager = CryptographyManager()
    private val ciphertextWrapper
        get() = context?.let {
            cryptographyManager.getCiphertextWrapperFromSharedPrefs(
                it,
                SHARED_PREFS_FILENAME,
                Context.MODE_PRIVATE,
                CIPHERTEXT_WRAPPER
            )
        }

    override fun onCreateView(
            inflater: LayoutInflater, container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View? {
        // Inflate the layout for this fragment
        val view = inflater.inflate(R.layout.fragment_b2c_bio_mode, container, false)

        // Creates a PublicClientApplication object with res/raw/auth_config_single_account.json
        PublicClientApplication.createMultipleAccountPublicClientApplication(context!!,
                R.raw.auth_config_b2c_bio,
                object : IMultipleAccountApplicationCreatedListener {
                    override fun onCreated(application: IMultipleAccountPublicClientApplication) {
                        b2cApp = application
                        loadAccounts()
                    }

                    override fun onError(exception: MsalException) {
                        displayError(exception)

                        btn_removeAccount!!.isEnabled = false
                        btn_runUserFlow!!.isEnabled = false
                        btn_useBioMetrics!!.isEnabled = false
                        btn_acquireTokenSilently!!.isEnabled = false
                        btn_enableBio!!.isEnabled = false
                    }
                })
        return view
    }

    /**
     * Initializes UI variables and callbacks.
     */
    private fun initializeUI() {

        val dataAdapter = ArrayAdapter<String>(
                context, android.R.layout.simple_spinner_item,
                object : ArrayList<String?>() {
                    init {
                        for (policyName in B2CBioConfiguration.Policies) add(policyName)
                    }
                }
        )
        dataAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        policy_list.setAdapter(dataAdapter)
        dataAdapter.notifyDataSetChanged()
        btn_runUserFlow.setOnClickListener(View.OnClickListener {
            if (b2cApp == null) {
                return@OnClickListener
            }
            val parameters = AcquireTokenParameters.Builder()
                    .startAuthorizationFromActivity(activity)
                    .fromAuthority(getAuthorityFromPolicyName(policy_list.getSelectedItem().toString()))
                    .withScopes(B2CConfiguration.scopes)
                    .withPrompt(Prompt.LOGIN)
                    .withCallback(authInteractiveCallback)
                    .build()

            b2cApp!!.acquireToken(parameters)
        })
        val canAuthenticate = context?.let { BiometricManager.from(it).canAuthenticate() }
        if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {

            btn_useBioMetrics!!.isEnabled=true
            btn_useBioMetrics.setOnClickListener(View.OnClickListener {
                if (b2cApp == null) {
                    return@OnClickListener
                }
                val parameters = AcquireTokenParameters.Builder()
                    .startAuthorizationFromActivity(activity)
                    .fromAuthority(
                        getAuthorityFromPolicyName(
                            policy_list.getSelectedItem().toString()
                        )
                    )
                    .withScopes(B2CConfiguration.scopes)
                    .withPrompt(Prompt.LOGIN)
                    .withCallback(authInteractiveBioCallback)
                    .build()

                b2cApp!!.acquireToken(parameters)
            })
        }

        btn_acquireTokenSilently.setOnClickListener(View.OnClickListener {
            if (b2cApp == null) {
                return@OnClickListener
            }

            ciphertextWrapper?.let { textWrapper ->
                val secretKeyName = "biometric_sample_encryption_key"
                val cipher = cryptographyManager.getInitializedCipherForDecryption(
                    secretKeyName, textWrapper.initializationVector
                )
                biometricPrompt =
                    BiometricPromptUtils.createBiometricPrompt(
                        theFrag.activity as AppCompatActivity,
                        ::decryptServerTokenFromStorage
                    )
                val promptInfo = BiometricPromptUtils.createPromptInfo(theFrag.activity as AppCompatActivity)
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
            }
        })

        btn_removeAccount.setOnClickListener(View.OnClickListener {
            if (b2cApp == null) {
                return@OnClickListener
            }
            val selectedUser = users!![user_list.getSelectedItemPosition()]
            selectedUser.signOutAsync(b2cApp!!,
                    object : RemoveAccountCallback {
                        override fun onRemoved() {
                            txt_log.setText("Signed Out.")
                            cryptographyManager.removeKeyStore("biometric_sample_encryption_key")
                            loadAccounts()
                        }

                        override fun onError(exception: MsalException) {
                            displayError(exception)
                        }
                    })
        })

        btn_stopBioMetrics.setOnClickListener(View.OnClickListener {
            txt_log.setText("Disabled BioMetrics MFA")
            cryptographyManager.removeKeyStore("biometric_sample_encryption_key")
            btn_enableBio!!.isEnabled = true
            loadAccounts()
        })

        btn_enableBio.setOnClickListener(View.OnClickListener {
            txt_log.setText("Enabling bio metrics for MFA")

            //get the account id of selected user list
            val selectedUser = users!![user_list.getSelectedItemPosition()]
            userid = selectedUser.userId.toString()

            val canAuthenticate = context?.let { BiometricManager.from(it).canAuthenticate() }
            if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
                val secretKeyName = "biometric_sample_encryption_key"
                cryptographyManager = CryptographyManager()
                val cipher = cryptographyManager.getInitializedCipherForEncryption(secretKeyName)
                val biometricPrompt =
                    BiometricPromptUtils.createBiometricPrompt(theFrag.activity as AppCompatActivity, ::encryptAndStoreServerTokenForFutureBioMfa)
                val promptInfo = BiometricPromptUtils.createPromptInfo(theFrag.activity as AppCompatActivity)
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
            }

            btn_enableBio!!.isEnabled = false
        })

    }

    private fun encryptAndStoreServerTokenForFutureBioMfa(authResult: BiometricPrompt.AuthenticationResult) {
        authResult.cryptoObject?.cipher?.apply {
            userid?.let { acctName ->
                Log.d(TAG, "The user name is $acctName")
                val encryptedServerTokenWrapper = cryptographyManager.encryptData(acctName, this)
                context?.let {
                    cryptographyManager.persistCiphertextWrapperToSharedPrefs(
                        encryptedServerTokenWrapper,
                        it,
                        SHARED_PREFS_FILENAME,
                        Context.MODE_PRIVATE,
                        CIPHERTEXT_WRAPPER
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        initializeUI()
    }

    private fun decryptServerTokenFromStorage(authResult: BiometricPrompt.AuthenticationResult) {
        ciphertextWrapper?.let { textWrapper ->
            authResult.cryptoObject?.cipher?.let {
                val plaintext =
                    cryptographyManager.decryptData(textWrapper.ciphertext, it)
                Log.d(TAG, "The user name is $plaintext")
                val selectedUser = users!!.first { u -> u.userId == plaintext }
                //val selectedUser = users!![user_list.getSelectedItemPosition()]
                selectedUser.acquireTokenSilentAsync(b2cApp!!,
                    policy_list.getSelectedItem().toString(),
                    B2CBioConfiguration.scopes,
                    authSilentCallback)
            }
        }
    }

    /**
     * Load signed-in accounts, if there's any.
     */
    private fun loadAccounts() {
        if (b2cApp == null) {
            return
        }
        b2cApp!!.getAccounts(object : LoadAccountsCallback {
            override fun onTaskCompleted(result: List<IAccount>) {
                users = B2CBioUser.getB2CBioUsersFromAccountList(result)
                updateUI(users)
            }

            override fun onError(exception: MsalException) {
                displayError(exception)
            }
        })
    }/* Tokens expired or no session, retry with interactive *//* Exception when communicating with the STS, likely config issue *//* Exception inside MSAL, more info inside MsalError.java *//* Failed to acquireToken *//* Successfully got a token. */

    /**
     * Callback used in for silent acquireToken calls.
     */
    private val authSilentCallback: SilentAuthenticationCallback
        private get() = object : SilentAuthenticationCallback {
            override fun onSuccess(authenticationResult: IAuthenticationResult) {
                Log.d(TAG, "Successfully authenticated")

                /* Successfully got a token. */displayResult(authenticationResult)
            }

            override fun onError(exception: MsalException) {
                /* Failed to acquireToken */
                Log.d(TAG, "Authentication failed: $exception")
                displayError(exception)
                if (exception is MsalClientException) {
                    /* Exception inside MSAL, more info inside MsalError.java */
                } else if (exception is MsalServiceException) {
                    /* Exception when communicating with the STS, likely config issue */
                } else if (exception is MsalUiRequiredException) {
                    /* Tokens expired or no session, retry with interactive */
                }
            }
        }/* User canceled the authentication *//* Exception when communicating with the STS, likely config issue *//* Exception inside MSAL, more info inside MsalError.java *//* Failed to acquireToken *//* Successfully got a token, use it to call a protected resource - MSGraph */

    /* display result info */

    /* Reload account asynchronously to get the up-to-date list. */
    /**
     * Callback used for interactive request.
     * If succeeds we use the access token to call the Microsoft Graph.
     * Does not check cache.
     */
    private val authInteractiveBioCallback: AuthenticationCallback
        private get() = object : AuthenticationCallback {
            var accountName = ""
            override fun onSuccess(authenticationResult: IAuthenticationResult) {
                /* Successfully got a token, use it to call a protected resource - MSGraph */
                Log.d(TAG, "Successfully authenticated")

                val account = authenticationResult.account
                accountName = account.id
                val canAuthenticate = context?.let { BiometricManager.from(it).canAuthenticate() }
                if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
                    val secretKeyName = "biometric_sample_encryption_key"
                    cryptographyManager = CryptographyManager()
                    val cipher = cryptographyManager.getInitializedCipherForEncryption(secretKeyName)
                    val biometricPrompt =
                        BiometricPromptUtils.createBiometricPrompt(theFrag.activity as AppCompatActivity, ::encryptAndStoreServerToken)
                    val promptInfo = BiometricPromptUtils.createPromptInfo(theFrag.activity as AppCompatActivity)
                    biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
                }

                /* turn off Enable Bio button since bio mfa just happened */
                btn_enableBio!!.isEnabled = false

                /* display result info */displayResult(authenticationResult)

                /* Reload account asynchronously to get the up-to-date list. */`loadAccounts`()
            }

            private fun encryptAndStoreServerToken(authResult: BiometricPrompt.AuthenticationResult) {
                authResult.cryptoObject?.cipher?.apply {
                    accountName?.let { acctName ->
                        Log.d(TAG, "The user name is $acctName")
                        val encryptedServerTokenWrapper = cryptographyManager.encryptData(acctName, this)
                        context?.let {
                            cryptographyManager.persistCiphertextWrapperToSharedPrefs(
                                encryptedServerTokenWrapper,
                                it,
                                SHARED_PREFS_FILENAME,
                                Context.MODE_PRIVATE,
                                CIPHERTEXT_WRAPPER
                            )
                        }
                    }
                }
            }

            override fun onError(exception: MsalException) {
                val B2C_PASSWORD_CHANGE = "AADB2C90118"
                if (exception.message!!.contains(B2C_PASSWORD_CHANGE)) {
                    txt_log!!.text = """
                        The user clicks the 'Forgot Password' link in a sign-up or sign-in user flow.
                        Your application needs to handle this error code by running a specific user flow that resets the password.
                        """.trimIndent()
                    return
                }

                /* Failed to acquireToken */Log.d(TAG, "Authentication failed: $exception")
                displayError(exception)
                if (exception is MsalClientException) {
                    /* Exception inside MSAL, more info inside MsalError.java */
                } else if (exception is MsalServiceException) {
                    /* Exception when communicating with the STS, likely config issue */
                }
            }

            override fun onCancel() {
                /* User canceled the authentication */
                Log.d(TAG, "User cancelled login.")
            }
        }


    private val authInteractiveCallback: AuthenticationCallback
        private get() = object : AuthenticationCallback {
            override fun onSuccess(authenticationResult: IAuthenticationResult) {
                /* Successfully got a token, use it to call a protected resource - MSGraph */
                Log.d(TAG, "Successfully authenticated")

                /* enable biometric mfa after user flow authN */
                btn_enableBio!!.isEnabled = true

                /* display result info */displayResult(authenticationResult)

                /* Reload account asynchronously to get the up-to-date list. */loadAccounts()
            }

            override fun onError(exception: MsalException) {
                val B2C_PASSWORD_CHANGE = "AADB2C90118"
                if (exception.message!!.contains(B2C_PASSWORD_CHANGE)) {
                    txt_log!!.text = """
                        The user clicks the 'Forgot Password' link in a sign-up or sign-in user flow.
                        Your application needs to handle this error code by running a specific user flow that resets the password.
                        """.trimIndent()
                    return
                }

                /* Failed to acquireToken */Log.d(TAG, "Authentication failed: $exception")
                displayError(exception)
                if (exception is MsalClientException) {
                    /* Exception inside MSAL, more info inside MsalError.java */
                } else if (exception is MsalServiceException) {
                    /* Exception when communicating with the STS, likely config issue */
                }

                btn_enableBio!!.isEnabled = false
            }

            override fun onCancel() {
                /* User canceled the authentication */
                Log.d(TAG, "User cancelled login.")
            }
        }
    //
    // Helper methods manage UI updates
    // ================================
    // displayResult() - Display the authentication result.
    // displayError() - Display the token error.
    // updateSignedInUI() - Updates UI when the user is signed in
    // updateSignedOutUI() - Updates UI when app sign out succeeds
    //
    /**
     * Display the graph response
     */
    private fun displayResult(result: IAuthenticationResult) {
        val output = """
         MSAL Cached User ID: ${result.account!!.id}
         Policy: ${result.account.claims!!["tfp"]}
         Display Name: ${result.account.claims!!["name"]}
         Given Name: ${result.account.claims!!["given_name"]}
         Family Name: ${result.account.claims!!["family_name"]}
         Audience: ${result.account.claims!!["aud"]}
         Object Id: ${result.account.claims!!["oid"]}
         Scope : ${result.scope.joinToString()}
         Expiry : ${result.expiresOn}
         Tenant ID : ${result.tenantId}
         
         """.trimIndent()
        Log.d(TAG, output)
        txt_log!!.text = output
    }

    /**
     * Display the error message
     */
    private fun displayError(exception: Exception) {
        txt_log!!.text = exception.toString()
    }

    /**
     * Updates UI based on the obtained user list.
     */
    private fun updateUI(users: List<B2CBioUser>?) {
        val canAuthenticate = context?.let { BiometricManager.from(it).canAuthenticate() }
        val hasSecret = cryptographyManager.getIsKeyStoreAvailable("biometric_sample_encryption_key")

        if (users!!.size != 0) {
            btn_removeAccount!!.isEnabled = true
            btn_acquireTokenSilently!!.isEnabled = (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS && hasSecret)
            btn_stopBioMetrics!!.isEnabled = (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS && hasSecret)
        } else {
            btn_removeAccount!!.isEnabled = false
            btn_acquireTokenSilently!!.isEnabled = false
            btn_stopBioMetrics!!.isEnabled = false
        }
        val dataAdapter = ArrayAdapter<String>(
                context, android.R.layout.simple_spinner_item,
                object : ArrayList<String?>() {
                    init {
                        for (user in users) add(user.displayName)
                    }
                }
        )
        dataAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        user_list!!.adapter = dataAdapter
        dataAdapter.notifyDataSetChanged()
    }

    companion object {
        private val TAG = B2CBioModeFragment::class.java.simpleName
    }
}