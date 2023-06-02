use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
};
use log;

use crate::sandbox::AccessFS;

impl AccessFS {
    fn read(&self) -> Option<&str> {
        if let Self::Read(path) = self {
            Some(path)
        } else {
            None
        }
    }

    fn read_write(&self) -> Option<&str> {
        if let Self::ReadWrite(path) = self {
            Some(path)
        } else {
            None
        }
    }

    fn make_reg(&self) -> Option<&str> {
        if let Self::MakeReg(path) = self {
            Some(path)
        } else {
            None
        }
    }

    fn make_dir(&self) -> Option<&str> {
        if let Self::MakeDir(path) = self {
            Some(path)
        } else {
            None
        }
    }
}

pub fn restrict_access(access_rules: &[AccessFS]) -> Result<(), Box<dyn std::error::Error>> {
    let abi = ABI::V1;

    let read_only: Vec<&str> = access_rules.iter().filter_map(AccessFS::read).collect();

    let read_write: Vec<&str> = access_rules
        .iter()
        .filter_map(AccessFS::read_write)
        .collect();

    let create_file: Vec<&str> = access_rules.iter().filter_map(AccessFS::make_reg).collect();

    let create_directory: Vec<&str> = access_rules.iter().filter_map(AccessFS::make_dir).collect();

    let status = Ruleset::new()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .add_rules(path_beneath_rules(read_only, AccessFs::from_read(abi)))?
        .add_rules(path_beneath_rules(read_write, AccessFs::from_all(abi)))?
        .add_rules(path_beneath_rules(create_file, AccessFs::MakeReg))?
        .add_rules(path_beneath_rules(create_directory, AccessFs::MakeDir))?
        .restrict_self()?;

    log::info!(
        "Activated FS access restrictions; rules={:?}, status={:?}",
        access_rules,
        status.ruleset
    );

    Ok(())
}
