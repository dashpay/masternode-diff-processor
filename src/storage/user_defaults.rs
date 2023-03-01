#[derive(Debug, Default)]
pub struct UserDefaults {

}
impl UserDefaults {

    pub fn set_integer_for_key(key: &str, value: i32) {
        todo!()
    }
    pub fn integer_for_key(key: &str) -> Option<i32> {
        todo!()
    }
    pub fn double_for_key(key: &str) -> Option<u64> {
        todo!()
    }
    pub fn has_key(key: &str) -> bool {
        todo!()
    }
    pub fn object_for_key<V>(key: &str) -> Option<V> {
        todo!()
    }

    pub fn string_for_key(key: &str) -> Option<String> {
        todo!()
    }

    pub fn remove_object_for_key(key: &str) {
        todo!()
    }

    pub fn set_object_for_key<V>(key: &str, value: V) {
        todo!()
    }

    pub fn has<T>(key: &str) -> bool {
        todo!()
    }

    pub fn get<T>(key: &str) -> Option<T> {
        todo!()
    }

    pub fn set<T>(key: &str, value: T) {
        todo!()
    }
}
