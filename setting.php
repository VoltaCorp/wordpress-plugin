<?php
add_action('admin_menu', 'volta_admin_actions');

function volta_admin_actions() {
    add_options_page('Volta Login', 'Volta Login', 'manage_options', __FILE__, 'volta_admin');
}

function volta_admin() {

    if (isset($_POST['save-volta-setting'])) {
        update_option('data-so-site-app-id', $_POST['data-so-site-app-id']);
        update_option('data-so-customer-api-key-public', $_POST['data-so-customer-api-key-public']);
        update_option('data-so-customer-api-key-private', $_POST['data-so-customer-api-key-private']);
        
        echo "<script type='text/javascript'>alert('Successfully Updated!'); </script>";
    }
   
    ?>

    <div> 
        <h3>Volta Login</h3>
        <table class="form-table">
            </br>
            <form action="" method="post">
     
                <tr>
                    <th scope="row"><label for="mailserver_login">APP ID</label></th>
                    <td><input type="text" name="data-so-site-app-id" value="<?php echo esc_attr(get_option('data-so-site-app-id')); ?>" size="40" required="required"/></td>
                </tr>
                <tr>
                    <th scope="row"><label for="mailserver_login"> PUBLIC KEY</label></th>
                    <td><input type="text" name="data-so-customer-api-key-public" value="<?php echo esc_attr(get_option('data-so-customer-api-key-public')); ?>" pattern="[/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/]+" size="40" required="required" /></td>
                </tr>
                <tr>
                    <th scope="row"><label for="mailserver_login">PRIVATE KEY</label></th>
                    <td><input type="text" name="data-so-customer-api-key-private" value="<?php echo esc_attr(get_option('data-so-customer-api-key-private')); ?>" pattern="[/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/]+" size="40" required="required" /></td>
                </tr>
                <tr><th scope="row"></th>
                    <td><input type="submit" class="button button-primary" name="save-volta-setting" value="Save"></td>
                </tr>
            </form>
    </div>

    <?php
}
?>

