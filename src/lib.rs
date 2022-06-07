//! Scan file through clamav 

use std::io::BufReader;
use std::fmt::Debug;

use tap::plugin;
use tap::config_schema;
use tap::attribute::Attributes;
use tap::plugin::{PluginInfo, PluginInstance, PluginConfig, PluginArgument, PluginResult, PluginEnvironment};
use tap::tree::{TreeNodeId, TreeNodeIdSchema};
use tap::error::RustructError;


use serde::{Serialize, Deserialize};
use schemars::{JsonSchema};
use anyhow::anyhow;

use clam_client::client::ClamClient;
use clam_client::response::ClamScanResult;

plugin!("clamav", "Malware", "ClamAV", ClamAvPlugin, Arguments);

#[derive(Debug, Serialize, Deserialize,JsonSchema)]
pub struct Arguments
{
  #[schemars(with = "TreeNodeIdSchema")] 
  file : TreeNodeId,
}

#[derive(Debug, Serialize, Deserialize,Default)]
pub struct Results
{
}

#[derive(Default)]
pub struct ClamAvPlugin
{
}

impl ClamAvPlugin
{
  fn run(&mut self, args : Arguments, env : PluginEnvironment) -> anyhow::Result<Results>
  {
    let file_node = env.tree.get_node_from_id(args.file).ok_or(RustructError::ArgumentNotFound("file"))?;
    let data = file_node.value().get_value("data").ok_or(RustructError::ValueNotFound("data"))?;
    let data_builder = data.try_as_vfile_builder().ok_or(RustructError::ValueTypeMismatch)?;
    let file = data_builder.open()?;

    let file = BufReader::new(file); 
    //use timeout or it will block thread indefinitely
    let client = ClamClient::new_with_timeout("127.0.0.1", 3310, 5).unwrap();

    

    let result = match client.scan_stream(file) 
    {
       //XXX use result
       Ok(result) => match result 
       {
          ClamScanResult::Ok => 
          { 
             file_node.value().add_attribute(self.name(), None, None); 
             Ok(Results{}) 
          },
          ClamScanResult::Found(_location, virus) => 
          {
            let mut attributes = Attributes::new();
            attributes.add_attribute("malware", virus, None);
            file_node.value().add_attribute(self.name(), attributes, None);
            Ok(Results{})
          },
          ClamScanResult::Error(err) =>
          {
            file_node.value().add_attribute(self.name(), None, None); 
            Err(anyhow!(err))
          },
        },
        Err(e) => 
        { 
          file_node.value().add_attribute(self.name(), None, None); 
          Err(anyhow!("A network error occurred while talking to ClamAV:\n{}", e))
        },
    };
    result
  }
}

