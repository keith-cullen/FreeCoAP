use super::*;

const SMALL_BUF_NUM: usize = 128;
const SMALL_BUF_LEN: usize = 256;
const MEDIUM_BUF_NUM: usize = 128;
const MEDIUM_BUF_LEN: usize = 1024;
const LARGE_BUF_NUM: usize = 32;
const LARGE_BUF_LEN: usize = 8192;

#[test]
fn simple_test() {
    unsafe {
        let ret = coap_mem_all_create(SMALL_BUF_NUM, SMALL_BUF_LEN,
                                      MEDIUM_BUF_NUM, MEDIUM_BUF_LEN,
                                      LARGE_BUF_NUM, LARGE_BUF_LEN);
        assert_eq!(ret, 0);
        let mut msg = coap_msg_t{
            ver: 0,
            type_: 0,
            token_len: 0,
            code_class: 0,
            code_detail: 0,
            msg_id: 0,
            token: [0; 8],
            op_list: coap_msg_op_list_t{
                first: std::ptr::null_mut(),
                last: std::ptr::null_mut()},
            payload: std::ptr::null_mut(),
            payload_len: 0};
        coap_msg_create(&mut msg as *mut _);
        let ret = coap_msg_set_type(&mut msg as *mut _, coap_msg_type_t_COAP_MSG_CON);
        assert_eq!(ret, 0);
        let ret = coap_msg_set_code(&mut msg as *mut _, 0x2, 0x4);
        assert_eq!(ret, 0);
        let ret = coap_msg_set_msg_id(&mut msg as *mut _, 100);
        assert_eq!(ret, 0);
        let mut token: [i8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let ret = coap_msg_set_token(&mut msg as *mut _, &mut token as *mut _, token.len());
        assert_eq!(ret, 0);
        let mut op_val: [i8; 4] = [0x21, 0x22, 0x23, 0x24];
        let ret = coap_msg_add_op(&mut msg as *mut _, coap_msg_op_num_t_COAP_MSG_URI_PATH, op_val.len() as u32, &mut op_val as *mut _);
        assert_eq!(ret, 0);
        let mut payload: [i8; 8] = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48];
        let ret = coap_msg_set_payload(&mut msg as *mut _, &mut payload as *mut _, payload.len());
        assert_eq!(ret, 0);
        coap_mem_all_destroy();
    }
}
