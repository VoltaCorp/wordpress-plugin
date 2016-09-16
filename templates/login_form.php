<?php if (true) : ?>
    <div class="login-form-container" style="width: 500px; margin: 0 auto;">
        <?php if ($attributes['show_title']) : ?>
            <h2><?php _e('Sign In', 'personalize-login'); ?></h2>
        <?php endif; ?>

        <!-- Show errors if there are any -->
        <?php if (count($attributes['errors']) > 0) : ?>
            <?php foreach ($attributes['errors'] as $error) : ?>
                <p class="login-error">
                    <?php echo $error; ?>
                </p>
            <?php endforeach; ?>
        <?php endif; ?>

        <!-- Show logged out message if user just logged out -->
        <?php if ($attributes['logged_out']) : ?>
            <p class="login-info">
                <?php _e('You have signed out. Would you like to sign in again?', 'personalize-login'); ?>
            </p>
        <?php endif; ?>

        <?php if ($attributes['registered']) : ?>
            <p class="login-info">
                <?php
                printf(
                        __('You have successfully registered to <strong>%s</strong>. We have emailed your password to the email address you entered.', 'personalize-login'), get_bloginfo('name')
                );
                ?>
            </p>
        <?php endif; ?>

        <?php if ($attributes['lost_password_sent']) : ?>
            <p class="login-info">
                <?php _e('Check your email for a link to reset your password.', 'personalize-login'); ?>
            </p>
        <?php endif; ?>

        <?php if ($attributes['password_updated']) : ?>
            <p class="login-info">
                <?php _e('Your password has been changed. You can sign in now.', 'personalize-login'); ?>
            </p>
        <?php endif; ?>

        <?php
        wp_login_form(
                array(
                    'label_username' => __('Email', 'personalize-login'),
                    'label_log_in' => __('Sign In', 'personalize-login'),
                    'redirect' => $attributes['redirect'],
                )
        );
        ?>

        <a class="forgot-password" href="<?php echo wp_lostpassword_url(); ?>">
            <?php _e('Forgot your password?', 'personalize-login'); ?>
        </a>

        <?php
//        wp_enqueue_style('bootstrap_min_css', plugins_url('/css/bootstrap.min.css', __DIR__));
//        wp_enqueue_style('bootstrap-theme_css', plugins_url('/css/bootstrap-theme.min.css', __DIR__));
//        wp_enqueue_script('bootstrap_min_js', plugins_url('/js/bootstrap.min.js', __DIR__));
//        wp_enqueue_style('bootstrap_css', 'https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css');
//        wp_enqueue_style('bootstrap_js', 'https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js');
//        wp_enqueue_style('bootstrap_theme', 'https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/css/bootstrap-theme.min.css');
        //wp_enqueue_style('volta', 'https://api.sineon.io/api/v1/resource/volta.css');
        //wp_enqueue_script('volta_js', plugins_url('volta.js', __DIR__), array('jquery'), null, true);
        //wp_enqueue_script('volta_so', plugins_url('so.js', __DIR__), array('jquery'), null, true);
        //wp_localize_script( 'volta_so', 'ajax_object', array( 'ajaxurl' => admin_url( 'admin-ajax.php' ) ) );

        add_filter('clean_url', 'unclean_url', 10, 3);

        function unclean_url($good_protocol_url, $original_url, $_context) {
            if (strpos($original_url, 'volta.js')) {
                remove_filter('clean_url', 'unclean_url', 10, 3);
                $url_parts = parse_url($good_protocol_url);
                return $url_parts['scheme'] . '://' . $url_parts['host'] . $url_parts['path'] . "' " . " class='so-init' data-so-customer-api-key-public='" . get_option('data-so-customer-api-key-public') . "' data-so-site-login-page-url='" . C_SO_SITE_LOGIN_PAGE_URL . "' data-so-site-authorized-resource-url='" . C_SO_SITE_AUTHORIZED_RESOURCE_URL . "' data-so-site-request-mode='direct' data-so-site-app-id='" . get_option('data-so-site-app-id') . "' data-so-login-form-index='1";
            }
            return $good_protocol_url;
        }

        if (!empty(get_option('data-so-site-app-id')) && !empty(get_option('data-so-customer-api-key-public')) && !empty(get_option('data-so-customer-api-key-private'))):
            wp_enqueue_script('volta_js', 'https://api.voltapass.com/api/v1/resource/volta.js', array('jquery'), null, true);
            ?>
            <div style="font-size: 30px;text-align: center;margin: 20px auto;">
                OR
            </div>
            <div id="so-login-container" class="SiteLoginContainer" style="margin: 20px auto;"></div>
    <?php endif; ?>

    </div>
    <?php else : ?>
    <div class="login-form-container">
        <form method="post" action="<?php echo wp_login_url(); ?>">
            <p class="login-username">
                <label for="user_login"><?php _e('Email', 'personalize-login'); ?></label>
                <input type="text" name="log" id="user_login">
            </p>
            <p class="login-password">
                <label for="user_pass"><?php _e('Password', 'personalize-login'); ?></label>
                <input type="password" name="pwd" id="user_pass">
            </p>
            <p class="login-submit">
                <input type="submit" value="<?php _e('Sign In', 'personalize-login'); ?>">
            </p>
        </form>
    </div>
<?php endif; ?>
