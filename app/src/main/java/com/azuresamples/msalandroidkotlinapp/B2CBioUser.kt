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

import com.azuresamples.msalandroidkotlinapp.B2CBioConfiguration.getAuthorityFromPolicyName
import com.microsoft.identity.client.AcquireTokenSilentParameters
import com.microsoft.identity.client.IAccount
import com.microsoft.identity.client.IMultipleAccountPublicClientApplication
import com.microsoft.identity.client.IMultipleAccountPublicClientApplication.RemoveAccountCallback
import com.microsoft.identity.client.SilentAuthenticationCallback
import com.microsoft.identity.client.exception.MsalException
import com.microsoft.identity.client.exception.MsalUiRequiredException
import com.microsoft.identity.common.internal.providers.oauth2.IDToken
import java.util.*

/**
 * Represents a B2C user.
 */
class B2CBioUser private constructor() {
    /**
     * List of account objects that are associated to this B2C user.
     */
    private val accounts: MutableList<IAccount> = ArrayList()// Make sure that all of your policies are returning the same set of claims.

    /**
     * Gets this user's display name.
     * If the value is not set, returns 'subject' instead.
     */
    val displayName: String?
        get() {
            if (accounts.isEmpty()) {
                return null
            }

            // Make sure that all of your policies are returning the same set of claims.
            val displayName = getB2CDisplayNameFromAccount(accounts[0])
            return displayName ?: getSubjectFromAccount(accounts[0])
        }

    val userId : String?
        get() {
            if(accounts.isEmpty()){
                return null
            }
            //7c94ba95-270b-4d4a-95fb-a0a680f2eec9-b2c_1_loyalty_susi
            var sub = getSubjectFromAccount(accounts[0])
            var tfp = getB2CPolicyNameFromAccount(accounts[0])

            // IMPORTANT: user id (secret encrypted value) comprises the subject (oid) along with the policy
            //  this way, same user doesn't reuse token from a different policy
            //  if this isn't an issue, secret key could be just oid
            val userid = sub + "-" + tfp!!.toLowerCase()
            return userid ?: getSubjectFromAccount(accounts[0])
        }
    /**
     * Acquires a token without interrupting the user.
     */
    fun acquireTokenSilentAsync(multipleAccountPublicClientApplication: IMultipleAccountPublicClientApplication,
                                policyName: String,
                                scopes: List<String?>?,
                                callback: SilentAuthenticationCallback) {
        for (account in accounts) {
            if (policyName.equals(getB2CPolicyNameFromAccount(account), ignoreCase = true)) {
                val parameters = AcquireTokenSilentParameters.Builder()
                        .fromAuthority(getAuthorityFromPolicyName(policyName))
                        .withScopes(scopes)
                        .forAccount(account)
                        .withCallback(callback)
                        .build()
                multipleAccountPublicClientApplication.acquireTokenSilentAsync(parameters)
                return
            }
        }
        callback.onError(
                MsalUiRequiredException(MsalUiRequiredException.NO_ACCOUNT_FOUND,
                        "Account associated to the policy is not found."))
    }

    /**
     * Signs the user out of your application.
     */
    fun signOutAsync(multipleAccountPublicClientApplication: IMultipleAccountPublicClientApplication,
                     callback: RemoveAccountCallback) {
        Thread {
            try {
                for (account in accounts) {
                    multipleAccountPublicClientApplication.removeAccount(account)
                }
                accounts.clear()
                callback.onRemoved()
            } catch (e: MsalException) {
                callback.onError(e)
            } catch (e: InterruptedException) {
                // Unexpected.
            }
        }.start()
    }

    companion object {
        /**
         * A factory method for generating B2C users based on the given IAccount list.
         */
        fun getB2CBioUsersFromAccountList(accounts: List<IAccount>): List<B2CBioUser> {
            val b2CUserHashMap = HashMap<String?, B2CBioUser>()
            for (account in accounts) {
                /**
                 * NOTE: Because B2C treats each policy as a separate authority, the access tokens, refresh tokens, and id tokens returned from each policy are considered logically separate entities.
                 * In practical terms, this means that each policy returns a separate IAccount object whose tokens cannot be used to invoke other policies.
                 *
                 * You can use the 'Subject' claim to identify that those accounts belong to the same user.
                 */
                val subject = getSubjectFromAccount(account)
                var user = b2CUserHashMap[subject]
                if (user == null) {
                    user = B2CBioUser()
                    b2CUserHashMap[subject] = user
                }
                user.accounts.add(account)
            }
            val users: MutableList<B2CBioUser> = ArrayList()
            users.addAll(b2CUserHashMap.values)
            return users
        }

        /**
         * Get name of the policy associated with the given B2C account.
         * See https://docs.microsoft.com/en-us/azure/active-directory-b2c/active-directory-b2c-reference-tokens for more info.
         */
        private fun getB2CPolicyNameFromAccount(account: IAccount): String? {
            return account.claims!!["tfp"] as String?
                    ?: // Fallback to "acr" (for older policies)
                    return account.claims!!["acr"] as String?
        }

        /**
         * Get subject of the given B2C account.
         *
         *
         * Subject is the principal about which the token asserts information, such as the user of an application.
         * See https://docs.microsoft.com/en-us/azure/active-directory-b2c/active-directory-b2c-reference-tokens for more info.
         */
        private fun getSubjectFromAccount(account: IAccount): String? {
            return account.claims!![IDToken.SUBJECT] as String?
        }

        /**
         * Get a displayable name of the given B2C account.
         * This claim is optional.
         */
        private fun getB2CDisplayNameFromAccount(account: IAccount): String? {
            val displayName = account.claims!![IDToken.NAME] ?: return null
            return displayName.toString()
        }
    }
}