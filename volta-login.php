<?php

/**
 * Plugin Name:       Volta Login
 * Description:       A plugin that replaces the WordPress login flow with a custom page.
 * Version:           1.0.0
 * Author:            Jarkko Laine
 * License:           GPL-2.0+
 * Text Domain:       personalize-login
 */
include 'setting.php';
//include_once _DIR_ . '/setting.php';
include_once __DIR__ . '/config.php';
//include_once __DIR__ . '/functions.php';
ini_set('display_errors', 1);
error_reporting(E_ALL);

if (isset($_POST['authToken']) && !empty($_POST['authToken'])) {

    function volta_login() {
        ini_set('display_errors', 1);
        error_reporting(E_ALL);

        $ch = curl_init();

        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'x-api-key-private: ' . get_option('data-so-customer-api-key-private'),
            'Accept: application/json',
            'Content-Type: application/x-www-form-urlencoded'
        ));
        curl_setopt($ch, CURLOPT_URL, "https://api.voltapass.com/api/v1/Authenticate/VerifyAuthState");
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, "applicationId=" . get_option('data-so-site-app-id') . "&authToken=" . $_POST['authToken']);

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $output = json_decode(curl_exec($ch), true);

        //print_r(curl_error($ch));
        //print_r($output);        die();

        curl_close($ch);
        //validate token by curl
        //validate username

        if (isset($output['user']) && isset($output['user']['email_address']) && !empty($output['user']['email_address'])) {  //
            $user = get_user_by('email', $output['user']['email_address']);
            // echo '<pre>';        print_r($user);            die();
            if ($user && isset($user->data) && isset($user->data->ID)) {
                $user_id = $user->data->ID;
                wp_set_current_user($user_id, $user->data->user_login);
                wp_set_auth_cookie($user_id);
                do_action('wp_login', $user_id);
                header('location: ' . get_bloginfo('url') . '/wp-admin');
                //wp_redirect(get_bloginfo('url') . '/wp-admin');
                die();
            }
            //header('location: ' . get_bloginfo('url') . '/wp-admin');
            wp_redirect(get_bloginfo('url') . '/wp-admin');
        } else {
            die('bc');
            // header('location: ' . get_bloginfo('url') . '/wp-admin');
            wp_redirect(get_bloginfo('url') . '/wp-admin');
        }

        /*
          if (isset($output['userId']) && !empty($output['userId'])) {  //
          $user = get_users(array('meta_key' => 'volta_user_id', 'meta_value' => $output['userId']));
          //echo '<pre>';        print_r($user);
          if ($user && is_array($user) && count($user) && isset($user[0]) && isset($user[0]->data) && isset($user[0]->data->ID)) {
          $user_id = $user[0]->data->ID;
          wp_set_current_user($user_id, $user[0]->data->ID);
          wp_set_auth_cookie($user_id);
          do_action('wp_login', $user[0]->data->ID);
          header('location: ' . get_bloginfo('url') . '/wp-admin');
          //wp_redirect(get_bloginfo('url') . '/wp-admin');
          die();
          }
          //header('location: ' . get_bloginfo('url') . '/wp-admin');
          wp_redirect(get_bloginfo('url') . '/wp-admin');
          } else {
          // header('location: ' . get_bloginfo('url') . '/wp-admin');
          wp_redirect(get_bloginfo('url') . '/wp-admin');
          }
         */
    }

    add_action('init', 'volta_login');
}

class Personalize_Login_Plugin {

    /**
     * Initializes the plugin.
     *
     * To keep the initialization fast, only add filter and action
     * hooks in the constructor.
     */
    public function __construct() {

        // Redirects
        add_action('login_form_login', array($this, 'redirect_to_custom_login'));
        add_filter('authenticate', array($this, 'maybe_redirect_at_authenticate'), 101, 3);
        add_filter('login_redirect', array($this, 'redirect_after_login'), 10, 3);
        // add_action('wp_logout', array($this, 'redirect_after_logout'));
//		add_action( 'login_form_register', array( $this, 'redirect_to_custom_register' ) );
//		add_action( 'login_form_lostpassword', array( $this, 'redirect_to_custom_lostpassword' ) );
//		add_action( 'login_form_rp', array( $this, 'redirect_to_custom_password_reset' ) );
//		add_action( 'login_form_resetpass', array( $this, 'redirect_to_custom_password_reset' ) );
//
//		// Handlers for form posting actions
//		add_action( 'login_form_register', array( $this, 'do_register_user' ) );
//		add_action( 'login_form_lostpassword', array( $this, 'do_password_lost' ) );
//		add_action( 'login_form_rp', array( $this, 'do_password_reset' ) );
//		add_action( 'login_form_resetpass', array( $this, 'do_password_reset' ) );
//
//		// Other customizations
//		add_filter( 'retrieve_password_message', array( $this, 'replace_retrieve_password_message' ), 10, 4 );
        // Setup
        add_action('wp_print_footer_scripts', array($this, 'add_captcha_js_to_footer'));
        //   add_filter('admin_init', array($this, 'register_settings_fields'));
        // Shortcodes
        add_shortcode('custom-login-form', array($this, 'render_login_form'));
//		add_shortcode( 'custom-register-form', array( $this, 'render_register_form' ) );
//		add_shortcode( 'custom-password-lost-form', array( $this, 'render_password_lost_form' ) );
//		add_shortcode( 'custom-password-reset-form', array( $this, 'render_password_reset_form' ) );
    }

    /**
     * Plugin activation hook.
     *
     * Creates all WordPress pages needed by the plugin.
     */
    public static function plugin_activated() {
        // Information needed for creating the plugin's pages
        $page_definitions = array(
            'member-login' => array(
                'title' => __('Sign In', 'personalize-login'),
                'content' => '[custom-login-form]'
            ),
//			'member-account' => array(
//				'title' => __( 'Your Account', 'personalize-login' ),
//				'content' => '[account-info]'
//			),
//			'member-register' => array(
//				'title' => __( 'Register', 'personalize-login' ),
//				'content' => '[custom-register-form]'
//			),
//			'member-password-lost' => array(
//				'title' => __( 'Forgot Your Password?', 'personalize-login' ),
//				'content' => '[custom-password-lost-form]'
//			),
//			'member-password-reset' => array(
//				'title' => __( 'Pick a New Password', 'personalize-login' ),
//				'content' => '[custom-password-reset-form]'
//			)
        );

        foreach ($page_definitions as $slug => $page) {
            // Check that the page doesn't exist already
            $query = new WP_Query('pagename=' . $slug);
            if (!$query->have_posts()) {
                // Add the page using the data from the array above
                wp_insert_post(
                        array(
                            'post_content' => $page['content'],
                            'post_name' => $slug,
                            'post_title' => $page['title'],
                            'post_status' => 'publish',
                            'post_type' => 'page',
                            'ping_status' => 'closed',
                            'comment_status' => 'closed',
                        )
                );
            }
        }
    }

    //
    // REDIRECT FUNCTIONS

    //

	/**
     * Redirect the user to the custom login page instead of wp-login.php.
     */
    public function redirect_to_custom_login() {
        if ($_SERVER['REQUEST_METHOD'] == 'GET') {
            if (is_user_logged_in()) {
                $this->redirect_logged_in_user();
                exit;
            }

            // The rest are redirected to the login page
            $login_url = home_url('member-login');
            if (!empty($_REQUEST['redirect_to'])) {
                $login_url = add_query_arg('redirect_to', $_REQUEST['redirect_to'], $login_url);
            }

            if (!empty($_REQUEST['checkemail'])) {
                $login_url = add_query_arg('checkemail', $_REQUEST['checkemail'], $login_url);
            }

            wp_redirect($login_url);
            exit;
        }
    }

    /**
     * Redirect the user after authentication if there were any errors.
     *
     * @param Wp_User|Wp_Error  $user       The signed in user, or the errors that have occurred during login.
     * @param string            $username   The user name used to log in.
     * @param string            $password   The password used to log in.
     *
     * @return Wp_User|Wp_Error The logged in user, or error information if there were errors.
     */
    public function maybe_redirect_at_authenticate($user, $username, $password) {
        // Check if the earlier authenticate filter (most likely,
        // the default WordPress authentication) functions have found errors
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (is_wp_error($user)) {
                $error_codes = join(',', $user->get_error_codes());

                $login_url = home_url('member-login');
                $login_url = add_query_arg('login', $error_codes, $login_url);

                wp_redirect($login_url);
                exit;
            }
        }

        return $user;
    }

    /**
     * Returns the URL to which the user should be redirected after the (successful) login.
     *
     * @param string           $redirect_to           The redirect destination URL.
     * @param string           $requested_redirect_to The requested redirect destination URL passed as a parameter.
     * @param WP_User|WP_Error $user                  WP_User object if login was successful, WP_Error object otherwise.
     *
     * @return string Redirect URL
     */
    public function redirect_after_login($redirect_to, $requested_redirect_to, $user) {
        $redirect_url = home_url();

        if (!isset($user->ID)) {
            return $redirect_url;
        }

        if (user_can($user, 'manage_options')) {
            // Use the redirect_to parameter if one is set, otherwise redirect to admin dashboard.
            if ($requested_redirect_to == '') {
                $redirect_url = admin_url();
            } else {
                $redirect_url = $redirect_to;
            }
        } else {
            // Non-admin users always go to their account page after login
            $redirect_url = home_url('member-account');
        }

        return wp_validate_redirect($redirect_url, home_url());
    }

    /**
     * Redirect to custom login page after the user has been logged out.
     */
    public function redirect_after_logout() {
        $redirect_url = home_url('member-login?logged_out=true');
        wp_redirect($redirect_url);
        exit;
    }

    /**
     * Redirects the user to the custom registration page instead
     * of wp-login.php?action=register.
     */
    public function redirect_to_custom_register() {
        if ('GET' == $_SERVER['REQUEST_METHOD']) {
            if (is_user_logged_in()) {
                $this->redirect_logged_in_user();
            } else {
                wp_redirect(home_url('member-register'));
            }
            exit;
        }
    }

    /**
     * Redirects the user to the custom "Forgot your password?" page instead of
     * wp-login.php?action=lostpassword.
     */
    public function redirect_to_custom_lostpassword() {
        if ('GET' == $_SERVER['REQUEST_METHOD']) {
            if (is_user_logged_in()) {
                $this->redirect_logged_in_user();
                exit;
            }

            wp_redirect(home_url('member-password-lost'));
            exit;
        }
    }

    /**
     * Redirects to the custom password reset page, or the login page
     * if there are errors.
     */
    public function redirect_to_custom_password_reset() {
        if ('GET' == $_SERVER['REQUEST_METHOD']) {
            // Verify key / login combo
            $user = check_password_reset_key($_REQUEST['key'], $_REQUEST['login']);
            if (!$user || is_wp_error($user)) {
                if ($user && $user->get_error_code() === 'expired_key') {
                    wp_redirect(home_url('member-login?login=expiredkey'));
                } else {
                    wp_redirect(home_url('member-login?login=invalidkey'));
                }
                exit;
            }

            $redirect_url = home_url('member-password-reset');
            $redirect_url = add_query_arg('login', esc_attr($_REQUEST['login']), $redirect_url);
            $redirect_url = add_query_arg('key', esc_attr($_REQUEST['key']), $redirect_url);

            wp_redirect($redirect_url);
            exit;
        }
    }

    //
    // FORM RENDERING SHORTCODES

    //

	/**
     * A shortcode for rendering the login form.
     *
     * @param  array   $attributes  Shortcode attributes.
     * @param  string  $content     The text content for shortcode. Not used.
     *
     * @return string  The shortcode output
     */
    public function render_login_form($attributes, $content = null) {



        // Parse shortcode attributes
        $default_attributes = array('show_title' => false);
        $attributes = shortcode_atts($default_attributes, $attributes);

        if (is_user_logged_in()) {
            return __('You are already signed in.', 'personalize-login');
        }

        // Pass the redirect parameter to the WordPress login functionality: by default,
        // don't specify a redirect, but if a valid redirect URL has been passed as
        // request parameter, use it.
        $attributes['redirect'] = '';
        if (isset($_REQUEST['redirect_to'])) {
            $attributes['redirect'] = wp_validate_redirect($_REQUEST['redirect_to'], $attributes['redirect']);
        }

        // Error messages
        $errors = array();
        if (isset($_REQUEST['login'])) {
            $error_codes = explode(',', $_REQUEST['login']);

            foreach ($error_codes as $code) {
                $errors [] = $this->get_error_message($code);
            }
        }
        $attributes['errors'] = $errors;

        // Check if user just logged out
        $attributes['logged_out'] = isset($_REQUEST['logged_out']) && $_REQUEST['logged_out'] == true;

        // Check if the user just registered
        $attributes['registered'] = isset($_REQUEST['registered']);

        // Check if the user just requested a new password
        $attributes['lost_password_sent'] = isset($_REQUEST['checkemail']) && $_REQUEST['checkemail'] == 'confirm';

        // Check if user just updated password
        $attributes['password_updated'] = isset($_REQUEST['password']) && $_REQUEST['password'] == 'changed';

        // Render the login form using an external template


        return $this->get_template_html('login_form', $attributes);
    }

    /**
     * An action function used to include the reCAPTCHA JavaScript file
     * at the end of the page.
     */
    public function add_captcha_js_to_footer() {
        echo "<script src='https://www.google.com/recaptcha/api.js?hl=en'></script>";
    }

    /**
     * Renders the contents of the given template to a string and returns it.
     *
     * @param string $template_name The name of the template to render (without .php)
     * @param array  $attributes    The PHP variables for the template
     *
     * @return string               The contents of the template.
     */
    private function get_template_html($template_name, $attributes = null) {
        if (!$attributes) {
            $attributes = array();
        }

        ob_start();

        do_action('personalize_login_before_' . $template_name);

        require( 'templates/' . $template_name . '.php');

        do_action('personalize_login_after_' . $template_name);

        $html = ob_get_contents();
        ob_end_clean();

        return $html;
    }

    //
    // HELPER FUNCTIONS

    //
	
	/**
     * Checks that the reCAPTCHA parameter sent with the registration
     * request is valid.
     *
     * @return bool True if the CAPTCHA is OK, otherwise false.
     */
    private function verify_recaptcha() {
        // This field is set by the recaptcha widget if check is successful
        if (isset($_POST['g-recaptcha-response'])) {
            $captcha_response = $_POST['g-recaptcha-response'];
        } else {
            return false;
        }

        // Verify the captcha response from Google
        $response = wp_remote_post(
                'https://www.google.com/recaptcha/api/siteverify', array(
            'body' => array(
                'secret' => get_option('personalize-login-recaptcha-secret-key'),
                'response' => $captcha_response
            )
                )
        );

        $success = false;
        if ($response && is_array($response)) {
            $decoded_response = json_decode($response['body']);
            $success = $decoded_response->success;
        }

        return $success;
    }

    /**
     * Redirects the user to the correct page depending on whether he / she
     * is an admin or not.
     *
     * @param string $redirect_to   An optional redirect_to URL for admin users
     */
    private function redirect_logged_in_user($redirect_to = null) {
        $user = wp_get_current_user();
        if (user_can($user, 'manage_options')) {
            if ($redirect_to) {
                wp_safe_redirect($redirect_to);
            } else {
                wp_redirect(admin_url());
            }
        } else {
            wp_redirect(home_url('member-account'));
        }
    }

    /**
     * Finds and returns a matching error message for the given error code.
     *
     * @param string $error_code    The error code to look up.
     *
     * @return string               An error message.
     */
    private function get_error_message($error_code) {
        switch ($error_code) {
            // Login errors

            case 'empty_username':
                return __('You do have an email address, right?', 'personalize-login');

            case 'empty_password':
                return __('You need to enter a password to login.', 'personalize-login');

            case 'invalid_username':
                return __(
                        "We don't have any users with that email address. Maybe you used a different one when signing up?", 'personalize-login'
                );

            case 'incorrect_password':
                $err = __(
                        "The password you entered wasn't quite right. <a href='%s'>Did you forget your password</a>?", 'personalize-login'
                );
                return sprintf($err, wp_lostpassword_url());

            // Registration errors

            case 'email':
                return __('The email address you entered is not valid.', 'personalize-login');

            case 'email_exists':
                return __('An account exists with this email address.', 'personalize-login');

            case 'closed':
                return __('Registering new users is currently not allowed.', 'personalize-login');

            case 'captcha':
                return __('The Google reCAPTCHA check failed. Are you a robot?', 'personalize-login');

            // Lost password

            case 'empty_username':
                return __('You need to enter your email address to continue.', 'personalize-login');

            case 'invalid_email':
            case 'invalidcombo':
                return __('There are no users registered with this email address.', 'personalize-login');

            // Reset password

            case 'expiredkey':
            case 'invalidkey':
                return __('The password reset link you used is not valid anymore.', 'personalize-login');

            case 'password_reset_mismatch':
                return __("The two passwords you entered don't match.", 'personalize-login');

            case 'password_reset_empty':
                return __("Sorry, we don't accept empty passwords.", 'personalize-login');

            default:
                break;
        }

        return __('An unknown error occurred. Please try again later.', 'personalize-login');
    }

    //
    // PLUGIN SETUP
    //
	
    public function render_recaptcha_site_key_field() {
        $value = get_option('personalize-login-recaptcha-site-key', '');
        echo '<input type="text" id="personalize-login-recaptcha-site-key" name="personalize-login-recaptcha-site-key" value="' . esc_attr($value) . '" />';
    }

    public function render_recaptcha_secret_key_field() {
        $value = get_option('personalize-login-recaptcha-secret-key', '');
        echo '<input type="text" id="personalize-login-recaptcha-secret-key" name="personalize-login-recaptcha-secret-key" value="' . esc_attr($value) . '" />';
    }

}

// Initialize the plugin
$personalize_login_pages_plugin = new Personalize_Login_Plugin();

// Create the custom pages at plugin activation
register_activation_hook(__FILE__, array('Personalize_Login_Plugin', 'plugin_activated'));
?>