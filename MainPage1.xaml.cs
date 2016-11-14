using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using System.Text;
using Windows.UI.Popups;

namespace encryption
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        string ciphertextString;
        private const string _encryptionKey = "My3ncRYpt10nK3y";
        public MainPage()
        {
            this.InitializeComponent();

            this.NavigationCacheMode = NavigationCacheMode.Required;
        }

        /// <summary>
        /// Invoked when this page is about to be displayed in a Frame.
        /// </summary>
        /// <param name="e">Event data that describes how this page was reached.
        /// This parameter is typically used to configure the page.</param>
        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            // TODO: Prepare page for display here.

            // TODO: If your application contains multiple pages, ensure that you are
            // handling the hardware Back button by registering for the
            // Windows.Phone.UI.Input.HardwareButtons.BackPressed event.
            // If you are using the NavigationHelper provided by some templates,
            // this event is handled for you.
        }

        private void AppBarButton_Click(object sender, RoutedEventArgs e)
        {
            


        }

        private static void _fn_generateKey(string _loc_password,string  _loc_salt, uint _loc_intCount, out IBuffer _loc_keyMaterial,out
        IBuffer _loc_iv)
        {
            //string _loc_salt = "this is me";
            //string _loc_password = "jkjkjksasa";
            //uint _loc_intCount = 1024;
            //IBuffer _loc_keyMaterial;
            //IBuffer _loc_iv;


            IBuffer _loc_saltBuffer = CryptographicBuffer.ConvertStringToBinary(_loc_salt, BinaryStringEncoding.Utf8);
            KeyDerivationParameters _loc_kdParameters = KeyDerivationParameters.BuildForPbkdf2(_loc_saltBuffer,_loc_intCount);
            KeyDerivationAlgorithmProvider _loc_kdf = KeyDerivationAlgorithmProvider.OpenAlgorithm(KeyDerivationAlgorithmNames.Pbkdf2Sha256);
            IBuffer _loc_pwordBuffer = CryptographicBuffer.ConvertStringToBinary(_loc_password, BinaryStringEncoding.Utf8);
            CryptographicKey _loc_pwordSourceKey = _loc_kdf.CreateKey(_loc_pwordBuffer);

            int _loc_keySize = 256/8;
            int _loc_ivSize = 128/8;
            uint _loc_ttlDataNeeded = (uint)(_loc_keySize + _loc_ivSize);
            IBuffer _loc_keyAndIv = CryptographicEngine.DeriveKeyMaterial(_loc_pwordSourceKey,_loc_kdParameters,_loc_ttlDataNeeded);

            byte[] _loc_keyMaterialBytes = _loc_keyAndIv.ToArray();
            _loc_keyMaterial = WindowsRuntimeBuffer.Create(_loc_keyMaterialBytes,0,_loc_keySize,_loc_keySize);
            _loc_iv = WindowsRuntimeBuffer.Create(_loc_keyMaterialBytes, _loc_keySize, _loc_ivSize, _loc_ivSize);
        //    return _loc_keyMaterial;
        }
        private void _fn_decription()
        {
            
        }

        private void _x_btn_encrypt_Click(object sender, RoutedEventArgs e)
        {
            IBuffer aesKeyMaterial;
            IBuffer iv;
            uint iterationCount = 10000;
            string passwordString = _x_tbx_password.Text;
            string saltString = "323232";
            _fn_generateKey(passwordString, saltString, iterationCount, out aesKeyMaterial, out iv);

            IBuffer plainText = CryptographicBuffer.ConvertStringToBinary(_x_tbx_encryptionData.Text, BinaryStringEncoding.Utf8);

            // Setup an AES key, using AES in CBC mode and applying PKCS#7 padding on the input
            SymmetricKeyAlgorithmProvider aesProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            CryptographicKey aesKey = aesProvider.CreateSymmetricKey(aesKeyMaterial);

            // Encrypt the data and convert it to a Base64 string
            IBuffer encrypted = CryptographicEngine.Encrypt(aesKey, plainText, iv);
            ciphertextString = CryptographicBuffer.EncodeToBase64String(encrypted);
            _x_tbx_decriptionData.Text = ciphertextString;
            if (ciphertextString.Length != 0)
            { _x_btn_send.IsEnabled = true; }
            else
            { _x_btn_send.IsEnabled = false; }
            _x_tbx_encryptionData.Text = "";
            _x_tbx_password.Text = "";

        }

        private void _x_btn_decrypt_Click(object sender, RoutedEventArgs e)
        {
            if ((_x_tbx_usrdecdata.Text.Length) != 0)
            {
                IBuffer aesKeyMaterial;
                IBuffer iv;
                uint iterationCount = 10000;
                string passwordString = _x_tbx_password.Text;
                string saltString = "323232";
                _fn_generateKey(passwordString, saltString, iterationCount, out aesKeyMaterial, out iv);

                // Setup an AES key, using AES in CBC mode and applying PKCS#7 padding on the input
                SymmetricKeyAlgorithmProvider aesProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
                CryptographicKey aesKey = aesProvider.CreateSymmetricKey(aesKeyMaterial);

                // Convert the base64 input to an IBuffer for decryption
                IBuffer ciphertext = CryptographicBuffer.DecodeFromBase64String(_x_tbx_usrdecdata.Text);

                // Decrypt the data and convert it back to a string
                IBuffer decrypted = CryptographicEngine.Decrypt(aesKey, ciphertext, iv);
                byte[] decryptedArray = decrypted.ToArray();
                string decryptedString = Encoding.UTF8.GetString(decryptedArray, 0, decryptedArray.Length);
                _x_tbx_text.Text = decryptedString;
            }
        }

        private async void _x_btn_send_Click(object sender, RoutedEventArgs e)
        {
                Windows.ApplicationModel.Chat.ChatMessage _chatMsg = new Windows.ApplicationModel.Chat.ChatMessage();
                _chatMsg.Body = ciphertextString;
                await Windows.ApplicationModel.Chat.ChatMessageManager.ShowComposeSmsMessageAsync(_chatMsg);
                _x_tbx_decriptionData.Text = "";
        }
    }
}
    
