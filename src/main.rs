#![allow(non_camel_case_types)]

mod ngap;

use asn1_codecs::aper::AperCodec;
use std::os::raw::{c_char, c_uint};
use entropic::prelude::*;
use std::io::Write;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use rand::{rngs::StdRng, RngCore, SeedableRng};

fn main() {

	let mut seen = HashMap::new();

    env_logger::init();


	//for i in 100..255u8 {
		let seed = [100u8; 32];
		let mut input = [0; 20_000];
		let mut rng: StdRng = SeedableRng::from_seed(seed);
		
		for i in 0..10000usize {
			println!("");

			rng.fill_bytes(&mut input);

			println!("{:?}", &input[0..100]);

			let Ok(im) = ngap::NGAP_PDU::from_entropy::<_, DefaultEntropyScheme>(input.iter()) else {
				println!("ERROR: insufficient bytes to construct initial PDU (skipping)");
				continue
			};
			println!("{:?}", im);

			let mut entropy = [0u8; 1_000_000];
			let entropy_len = im.to_entropy::<_, DefaultEntropyScheme>(entropy.iter_mut()).unwrap();

			println!("entropy_len: {}", entropy_len);
			println!("entropy: {:?}", &entropy[..entropy_len]);

			let chk_pkt = ngap::NGAP_PDU::from_entropy::<_, DefaultEntropyScheme>(&entropy[..entropy_len]).unwrap();
			println!("{:?}", chk_pkt);

			let mut encoded = asn1_codecs::PerCodecData::new_aper();
			match im.aper_encode(&mut encoded) {
				Ok(()) => {
					let bytes = encoded.into_bytes();
					let mut encoded = asn1_codecs::PerCodecData::from_slice_aper(bytes.as_slice());
					let filetype = match im {
						ngap::NGAP_PDU::InitiatingMessage(i) => {
							match i.value {
								ngap::InitiatingMessageValue::Id_AMFCPRelocationIndication(_) => "amfcp_relocation_indication",
								ngap::InitiatingMessageValue::Id_AMFConfigurationUpdate(_) => "amf_configuration_update",
								ngap::InitiatingMessageValue::Id_AMFStatusIndication(_) => "amf_status_indication",
								ngap::InitiatingMessageValue::Id_CellTrafficTrace(_) => "cell_traffic_trace",
								ngap::InitiatingMessageValue::Id_ConnectionEstablishmentIndication(_) => "connection_establishment_indication",
								ngap::InitiatingMessageValue::Id_DeactivateTrace(_) => "deactivate_trace",
								ngap::InitiatingMessageValue::Id_DownlinkNASTransport(_) => "downlink_nas_transport",
								ngap::InitiatingMessageValue::Id_DownlinkNonUEAssociatedNRPPaTransport(_) => "downlink_non_ue_associated_nrppa_transport",
								ngap::InitiatingMessageValue::Id_DownlinkRANConfigurationTransfer(_) => "downlink_ran_configuration_transfer",
								ngap::InitiatingMessageValue::Id_DownlinkRANEarlyStatusTransfer(_) => "downlink_ran_early_status_transfer",
								ngap::InitiatingMessageValue::Id_DownlinkRANStatusTransfer(_) => "downlink_ran_status_transfer",
								ngap::InitiatingMessageValue::Id_DownlinkRIMInformationTransfer(_) => "downlink_rim_information_transfer",
								ngap::InitiatingMessageValue::Id_DownlinkUEAssociatedNRPPaTransport(_) => "downlink_ue_association_nrppa_transport",
								ngap::InitiatingMessageValue::Id_ErrorIndication(_) => "error_indication",
								ngap::InitiatingMessageValue::Id_HandoverCancel(_) => "handover_cancel",
								ngap::InitiatingMessageValue::Id_HandoverNotification(_) => "handover_notification",
								ngap::InitiatingMessageValue::Id_HandoverPreparation(_) => "handover_preparation",
								ngap::InitiatingMessageValue::Id_HandoverResourceAllocation(_) => "handover_resource_allocation",
								ngap::InitiatingMessageValue::Id_HandoverSuccess(_) => "handover_success",
								ngap::InitiatingMessageValue::Id_InitialContextSetup(_) => "initial_context_setup",
								ngap::InitiatingMessageValue::Id_InitialUEMessage(_) => "initial_ue_message",
								ngap::InitiatingMessageValue::Id_LocationReport(_) => "location_report",
								ngap::InitiatingMessageValue::Id_LocationReportingControl(_) => "location_reporting_control",
								ngap::InitiatingMessageValue::Id_LocationReportingFailureIndication(_) => "location_reporting_failure_indication",
								ngap::InitiatingMessageValue::Id_NASNonDeliveryIndication(_) => "nas_non_delivery_indication",
								ngap::InitiatingMessageValue::Id_NGReset(_) => "ng_reset",
								ngap::InitiatingMessageValue::Id_NGSetup(_) => "ng_setup",
								ngap::InitiatingMessageValue::Id_OverloadStart(_) => "overload_start",
								ngap::InitiatingMessageValue::Id_OverloadStop(_) => "overload_stop",
								ngap::InitiatingMessageValue::Id_PDUSessionResourceModify(_) => "pdu_session_resource_modify",
								ngap::InitiatingMessageValue::Id_PDUSessionResourceModifyIndication(_) => "pdu_session_resource_modify_indication",
								ngap::InitiatingMessageValue::Id_PDUSessionResourceNotify(_) => "pdu_session_resourcenotify",
								ngap::InitiatingMessageValue::Id_PDUSessionResourceRelease(_) => "pdu_session_resource_release",
								ngap::InitiatingMessageValue::Id_PDUSessionResourceSetup(_) => "pdu_session_resource_setup",
								ngap::InitiatingMessageValue::Id_PWSCancel(_) => "pws_cancel",
								ngap::InitiatingMessageValue::Id_PWSFailureIndication(_) => "pws_failure_indication",
								ngap::InitiatingMessageValue::Id_PWSRestartIndication(_) => "pws_restart_indication",
								ngap::InitiatingMessageValue::Id_Paging(_) => "paging",
								ngap::InitiatingMessageValue::Id_PathSwitchRequest(_) => "path_switch_request",
								ngap::InitiatingMessageValue::Id_PrivateMessage(_) => "private_message",
								ngap::InitiatingMessageValue::Id_RANCPRelocationIndication(_) => "ran_cp_relocation_indication",
								ngap::InitiatingMessageValue::Id_RANConfigurationUpdate(_) => "ran_configuration_update",
								ngap::InitiatingMessageValue::Id_RRCInactiveTransitionReport(_) => "rrc_inactive_transition_report",
								ngap::InitiatingMessageValue::Id_RerouteNASRequest(_) => "reroute_nas_request",
								ngap::InitiatingMessageValue::Id_RetrieveUEInformation(_) => "retrieve_ue_information",
								ngap::InitiatingMessageValue::Id_SecondaryRATDataUsageReport(_) => "secondary_rat_data_usage_report",
								ngap::InitiatingMessageValue::Id_TraceFailureIndication(_) => "trace_failure_indication",
								ngap::InitiatingMessageValue::Id_TraceStart(_) => "trace_start",
								ngap::InitiatingMessageValue::Id_UEContextModification(_) => "ue_context_modification",
								ngap::InitiatingMessageValue::Id_UEContextRelease(_) => "ue_context_release",
								ngap::InitiatingMessageValue::Id_UEContextReleaseRequest(_) => "ue_context_release_request",
								ngap::InitiatingMessageValue::Id_UEContextResume(_) => "ue_context_resume",
								ngap::InitiatingMessageValue::Id_UEContextSuspend(_) => "ue_context_suspend",
								ngap::InitiatingMessageValue::Id_UEInformationTransfer(_) => "ue_information_transfer",
								ngap::InitiatingMessageValue::Id_UERadioCapabilityCheck(_) => "ue_radio_capability_check",
								ngap::InitiatingMessageValue::Id_UERadioCapabilityIDMapping(_) => "ue_radio_capability_id_mapping",
								ngap::InitiatingMessageValue::Id_UERadioCapabilityInfoIndication(_) => "ue_radio_capability_info_indication",
								ngap::InitiatingMessageValue::Id_UETNLABindingRelease(_) => "ue_tnla_binding_release",
								ngap::InitiatingMessageValue::Id_UplinkNASTransport(_) => "uplink_nas_transport",
								ngap::InitiatingMessageValue::Id_UplinkNonUEAssociatedNRPPaTransport(_) => "uplink_non_ue_associated_nrppa_transport",
								ngap::InitiatingMessageValue::Id_UplinkRANConfigurationTransfer(_) => "uplink_ran_configuration_transfer",
								ngap::InitiatingMessageValue::Id_UplinkRANEarlyStatusTransfer(_) => "uplink_ran_early_status_transfer",
								ngap::InitiatingMessageValue::Id_UplinkRANStatusTransfer(_) => "uplink_ran_status_transfer",
								ngap::InitiatingMessageValue::Id_UplinkRIMInformationTransfer(_) => "uplink_rim_information_transfer",
								ngap::InitiatingMessageValue::Id_UplinkUEAssociatedNRPPaTransport(_) => "uplink_ue_associated_nrppa_transport",
								ngap::InitiatingMessageValue::Id_WriteReplaceWarning(_) => "write_replace_warning",
								_ => "unknown",
							}
						}
						ngap::NGAP_PDU::SuccessfulOutcome(_) => "successful_outcome",
						ngap::NGAP_PDU::UnsuccessfulOutcome(_) => "unsuccessful_outcome",
					};
					let filename = format!("{}_{}.aper", filetype, i);

					let value = match seen.entry(filetype) {
						Entry::Occupied(o) => o.into_mut(),
						Entry::Vacant(v) => v.insert(0usize),
					};
					
					if *value < 2 {
						match ngap::NGAP_PDU::aper_decode(&mut encoded) {
							Ok(im_new) => {
								std::fs::write(filename, bytes.as_slice()).unwrap();
								std::fs::write(format!("{}_{}.aper.structured", filetype, i), &entropy[..entropy_len]).unwrap();
								*value += 1;
							},
							Err(e) => {
								println!("{} reencode failed: {}", filename, e);
								// std::fs::write(filename, bytes.as_slice()).unwrap();
							},
						}
					}
					
					
				},
				Err(e) => println!("Unable to generate message from bytes: {}", e),
			}
        }
    //}
}

